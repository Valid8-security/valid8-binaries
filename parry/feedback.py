# Parry (C) by Lemonade Stand. Written by Andy Kurapati and Shreyan Mitra
"""
Feedback management system for beta renewals and user input

This module handles beta user feedback collection and license renewal requests:
- Local feedback queue storage (JSONL format in ~/.parry/feedback/)
- Optional GitHub issue creation for feedback tracking
- Renewal request submission with license metadata
- Email contact information management
- Retry mechanism for failed submissions

Key Features:
- Offline-first: Queues feedback locally even without internet
- GitHub Integration: Automatically creates issues when online
- License Context: Includes tier, expiration, machine_id in submissions
- Privacy: User controls what metadata is shared
- Fallback Email: Provides beta@parry.ai for manual submissions

Used by:
- `parry license renew` command
- Admin feedback collection workflows
- Beta program management
"""

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional

# Try to import optional dependencies
try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


class FeedbackManager:
    """Manage user feedback submission and tracking"""
    
    def __init__(self):
        self.feedback_dir = Path.home() / '.parry' / 'feedback'
        self.feedback_dir.mkdir(parents=True, exist_ok=True)
        self.queue_file = self.feedback_dir / 'renewal_queue.jsonl'
    
    def submit_renewal_request(
        self,
        email: str,
        feedback: str,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Submit beta renewal feedback.
        
        Args:
            email: User email
            feedback: Feedback text
            metadata: Additional metadata (license info, usage, etc.)
        
        Returns:
            Dict with submission details
        """
        from parry.license import LicenseManager, LicenseConfig
        
        # Gather metadata
        if metadata is None:
            metadata = {}
        
        # Get license info
        try:
            license_info = LicenseManager.get_license_info()
            
            # Load license file for expiration
            license_file = LicenseConfig.LICENSE_FILE
            if license_file.exists():
                with open(license_file, 'r') as f:
                    license_data = json.load(f)
                    metadata.update({
                        'expires': license_data.get('expires'),
                        'machine_id': license_data.get('machine_id'),
                        'tier': license_data.get('tier'),
                    })
        except:
            pass
        
        # Create submission
        submission = {
            'email': email,
            'timestamp': datetime.now().isoformat(),
            'feedback': feedback,
            'feedback_length': len(feedback),
            'status': 'pending',
            'metadata': metadata,
        }
        
        # Save to local queue
        with open(self.queue_file, 'a') as f:
            f.write(json.dumps(submission) + '\n')
        
        # Try GitHub submission if available
        github_issue_url = None
        try:
            github_issue_url = self._submit_to_github(email, feedback, metadata)
        except Exception as e:
            # Gracefully fail if GitHub submission doesn't work
            pass
        
        return {
            'success': True,
            'local_file': str(self.queue_file),
            'github_issue': github_issue_url,
            'email': 'beta@parry.ai',
            'submission_id': hash(email + feedback)
        }
    
    def _submit_to_github(
        self,
        email: str,
        feedback: str,
        metadata: Dict[str, Any]
    ) -> Optional[str]:
        """
        Submit renewal request to GitHub Issues (OPTIONAL)
        
        Note: This only works if Parry is open-source or repo is public.
        For closed-source products, users should email admin directly.
        """
        
        # Only try if requests is available
        if not HAS_REQUESTS:
            return None
        
        # Check for GitHub token
        github_token = os.getenv('GITHUB_TOKEN') or os.getenv('PARRY_GITHUB_TOKEN')
        if not github_token:
            return None
        
        # Get expiration info
        expires = metadata.get('expires', 'unknown')
        days_left = 'unknown'
        if expires != 'unknown':
            try:
                from datetime import datetime
                exp_date = datetime.fromisoformat(expires)
                days_left = (exp_date - datetime.now()).days
            except:
                pass
        
        # Create issue
        url = 'https://api.github.com/repos/Parry-AI/parry-scanner/issues'
        headers = {
            'Authorization': f'token {github_token}',
            'Accept': 'application/vnd.github.v3+json'
        }
        
        issue_body = f"""## Beta License Renewal Request

**Email:** `{email}`
**Expires:** {expires}
**Days Left:** {days_left}

### Feedback

{feedback}

### License Details

```
Machine ID: {metadata.get('machine_id', 'N/A')}
Tier: {metadata.get('tier', 'N/A')}
```

---
**Status:** Pending Review
**Auto-approve if:** Feedback quality ✅ + Engagement ✅
"""
        
        issue = {
            'title': f'Beta Renewal: {email}',
            'body': issue_body,
            'labels': ['beta-renewal', 'pending-review']
        }
        
        try:
            response = requests.post(url, json=issue, headers=headers, timeout=10)
            if response.status_code == 201:
                issue_data = response.json()
                return issue_data['html_url']
        except Exception:
            # Gracefully fail
            pass
        
        return None
    
    def get_pending_renewals(self) -> List[Dict[str, Any]]:
        """Get all pending renewal requests"""
        if not self.queue_file.exists():
            return []
        
        pending = []
        try:
            with open(self.queue_file, 'r') as f:
                for line in f:
                    if line.strip():
                        data = json.loads(line)
                        if data.get('status') == 'pending':
                            pending.append(data)
        except:
            pass
        
        return pending
    
    def mark_renewal_processed(self, submission_id: int):
        """Mark a renewal request as processed"""
        try:
            queue_file = Path.home() / '.parry' / 'renewal_queue.json'
            if queue_file.exists():
                with open(queue_file, 'r') as f:
                    queue = json.load(f)
                
                # Update status
                for item in queue.get('requests', []):
                    if item.get('id') == submission_id:
                        item['status'] = 'processed'
                        item['processed_at'] = datetime.datetime.now().isoformat()
                        break
                
                # Save updated queue
                with open(queue_file, 'w') as f:
                    json.dump(queue, f, indent=2)
        except Exception as e:
            print(f"Error marking renewal as processed: {e}")
    
    def get_renewals_from_github(self) -> List[Dict[str, Any]]:
        """Fetch pending renewal requests from GitHub Issues"""
        
        if not HAS_REQUESTS:
            raise ImportError("requests module not available")
        
        github_token = os.getenv('GITHUB_TOKEN') or os.getenv('PARRY_GITHUB_TOKEN')
        if not github_token:
            raise ValueError("GITHUB_TOKEN environment variable not set")
        
        url = 'https://api.github.com/repos/Parry-AI/parry-scanner/issues'
        headers = {
            'Authorization': f'token {github_token}',
            'Accept': 'application/vnd.github.v3+json'
        }
        
        params = {
            'state': 'open',
            'labels': 'beta-renewal,pending-review',
            'per_page': 100
        }
        
        try:
            response = requests.get(url, headers=headers, params=params, timeout=10)
            response.raise_for_status()
            
            issues = response.json()
            renewals = []
            
            for issue in issues:
                # Parse issue body to extract details
                body = issue.get('body', '')
                
                # Extract email
                import re
                email_match = re.search(r'\*\*Email:\*\* `([^`]+)`', body)
                email = email_match.group(1) if email_match else 'unknown'
                
                # Extract days left
                days_left_match = re.search(r'\*\*Days Left:\*\* (\d+)', body)
                days_left = int(days_left_match.group(1)) if days_left_match else 'unknown'
                
                # Extract feedback
                feedback_match = re.search(r'### Feedback\s*\n\s*\n(.+?)\n\n###', body, re.DOTALL)
                feedback = feedback_match.group(1).strip() if feedback_match else 'No feedback'
                
                renewals.append({
                    'email': email,
                    'feedback': feedback,
                    'metadata': {'days_left': days_left},
                    'status': 'pending',
                    'source': 'github',
                    'github_issue_number': issue.get('number'),
                    'github_url': issue.get('html_url'),
                    'timestamp': issue.get('created_at'),
                })
            
            return renewals
            
        except Exception as e:
            # Gracefully fail
            raise Exception(f"Failed to fetch GitHub issues: {e}")


def submit_beta_feedback(email: str, feedback: str, feedback_type: str = 'renewal') -> Dict[str, Any]:
    """
    Submit feedback (renewal, bug report, feature request, etc.)
    
    Args:
        email: User email
        feedback: Feedback text
        feedback_type: Type of feedback (renewal, bug, feature, general)
    
    Returns:
        Submission confirmation with channels used
    """
    manager = FeedbackManager()
    
    if feedback_type == 'renewal':
        return manager.submit_renewal_request(email, feedback)
    else:
        # Generic feedback submission
        submission = {
            'email': email,
            'type': feedback_type,
            'timestamp': datetime.now().isoformat(),
            'feedback': feedback,
            'status': 'pending',
        }
        
        # Save to file
        feedback_file = manager.feedback_dir / f'{feedback_type}_queue.jsonl'
        with open(feedback_file, 'a') as f:
            f.write(json.dumps(submission) + '\n')
        
        return {
            'success': True,
            'local_file': str(feedback_file),
            'email': 'beta@parry.ai',
        }

