#!/usr/bin/env python3
"""
Enterprise Billing and Subscription Management System

Handles enterprise customers with:
- Seat-based pricing
- Organization management
- Advanced billing features
- Custom contracts
- Usage analytics
- Compliance reporting
"""

import os
import json
import time
import uuid
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from pathlib import Path

try:
    import stripe
    STRIPE_AVAILABLE = True
except ImportError:
    STRIPE_AVAILABLE = False

try:
    from .payment.stripe_integration import PaymentConfig, SubscriptionTier
except ImportError:
    # Define fallback classes if payment module not available
    from dataclasses import dataclass

    @dataclass
    class SubscriptionTier:
        name: str
        price_monthly: int
        price_yearly: int
        features: list
        file_limit: Optional[int] = None
        llm_mode: str = 'local'

    class PaymentConfig:
        TIERS = {
            'free': SubscriptionTier('Free', 0, 0, [], 100, 'local'),
            'pro': SubscriptionTier('Pro', 2900, 24900, [], None, 'hosted'),
            'enterprise': SubscriptionTier('Enterprise', 9900, 89000, [], None, 'hosted')
        }


@dataclass
class Organization:
    """Enterprise organization/tenant"""
    id: str
    name: str
    domain: str
    admin_email: str
    subscription_tier: str
    seats_allocated: int
    seats_used: int
    monthly_scan_limit: Optional[int]
    scans_used_this_month: int
    api_rate_limit: int
    custom_features: List[str]
    sso_enabled: bool
    sso_provider: Optional[str]
    contract_start_date: datetime
    contract_end_date: Optional[datetime]
    billing_email: str
    support_level: str
    created_at: datetime
    updated_at: datetime


@dataclass
class SeatAssignment:
    """Seat assignment to team member"""
    id: str
    organization_id: str
    user_email: str
    user_name: str
    role: str  # admin, developer, auditor, readonly
    assigned_at: datetime
    last_active: Optional[datetime]
    license_key: str


@dataclass
class EnterpriseUsage:
    """Enterprise usage tracking"""
    organization_id: str
    period_start: datetime
    period_end: datetime
    scans_total: int
    scans_by_detector: Dict[str, int]
    api_calls_total: int
    api_calls_by_endpoint: Dict[str, int]
    active_users: int
    storage_used_gb: float
    compliance_scans: int
    custom_rules_used: int
    federated_learning_sessions: int


class EnterpriseBillingManager:
    """Manage enterprise billing, organizations, and seat management"""

    def __init__(self):
        self.config = PaymentConfig()
        self.organizations_file = Path.home() / '.parry' / 'organizations.json'
        self.seats_file = Path.home() / '.parry' / 'seats.json'
        self.usage_file = Path.home() / '.parry' / 'enterprise_usage.json'

        # Ensure directories exist
        self.organizations_file.parent.mkdir(exist_ok=True)

        if STRIPE_AVAILABLE:
            stripe.api_key = self.config.STRIPE_SECRET_KEY

    def create_organization(
        self,
        name: str,
        domain: str,
        admin_email: str,
        tier: str,
        seats: int,
        custom_contract: bool = False
    ) -> Organization:
        """
        Create new enterprise organization

        Args:
            name: Organization name
            domain: Organization domain
            admin_email: Admin contact email
            tier: Subscription tier (pro/enterprise/enterprise_custom)
            seats: Number of seats to allocate
            custom_contract: Whether this is a custom contract

        Returns:
            Created organization
        """
        org_id = str(uuid.uuid4())

        # Calculate pricing based on tier and seats
        tier_config = self.config.TIERS[tier]

        # For enterprise tier, price is per seat
        if tier == 'enterprise':
            monthly_price = tier_config.price_monthly * seats
            yearly_price = tier_config.price_yearly * seats
        elif custom_contract:
            # Custom pricing - will be set during contract negotiation
            monthly_price = 0
            yearly_price = 0
        else:
            monthly_price = tier_config.price_monthly
            yearly_price = tier_config.price_yearly

        # Set limits based on tier
        if tier == 'enterprise':
            monthly_scan_limit = None  # Unlimited
            api_rate_limit = 10000  # 10k requests/hour
            support_level = 'priority'
        elif tier == 'pro':
            monthly_scan_limit = 50000  # 50k scans/month
            api_rate_limit = 1000   # 1k requests/hour
            support_level = 'email'
        else:
            monthly_scan_limit = 1000
            api_rate_limit = 100
            support_level = 'community'

        org = Organization(
            id=org_id,
            name=name,
            domain=domain,
            admin_email=admin_email,
            subscription_tier=tier,
            seats_allocated=seats,
            seats_used=0,
            monthly_scan_limit=monthly_scan_limit,
            scans_used_this_month=0,
            api_rate_limit=api_rate_limit,
            custom_features=[],
            sso_enabled=False,
            sso_provider=None,
            contract_start_date=datetime.now(),
            contract_end_date=None,
            billing_email=admin_email,
            support_level=support_level,
            created_at=datetime.now(),
            updated_at=datetime.now()
        )

        # Save organization
        self._save_organization(org)

        # Create initial seat for admin
        self.assign_seat(org_id, admin_email, f"{name} Admin", 'admin')

        return org

    def assign_seat(
        self,
        organization_id: str,
        user_email: str,
        user_name: str,
        role: str = 'developer'
    ) -> SeatAssignment:
        """
        Assign a seat to a team member

        Args:
            organization_id: Organization ID
            user_email: User email
            user_name: User display name
            role: User role (admin/developer/auditor/readonly)

        Returns:
            Seat assignment
        """
        # Check organization exists and has available seats
        org = self.get_organization(organization_id)
        if not org:
            raise ValueError(f"Organization {organization_id} not found")

        if org.seats_used >= org.seats_allocated:
            raise ValueError(f"No available seats in organization {org.name}")

        # Generate license key for user
        license_key = self._generate_user_license_key(organization_id, user_email, role)

        seat = SeatAssignment(
            id=str(uuid.uuid4()),
            organization_id=organization_id,
            user_email=user_email,
            user_name=user_name,
            role=role,
            assigned_at=datetime.now(),
            last_active=None,
            license_key=license_key
        )

        # Save seat assignment
        self._save_seat_assignment(seat)

        # Update organization seat count
        org.seats_used += 1
        org.updated_at = datetime.now()
        self._save_organization(org)

        return seat

    def revoke_seat(self, organization_id: str, user_email: str) -> bool:
        """
        Revoke a seat assignment

        Args:
            organization_id: Organization ID
            user_email: User email to revoke

        Returns:
            True if successful
        """
        seats = self._load_seat_assignments()
        updated_seats = []

        seat_found = False
        for seat in seats:
            if seat['organization_id'] == organization_id and seat['user_email'] == user_email:
                seat_found = True
                # Don't add to updated_seats (removes it)
            else:
                updated_seats.append(seat)

        if seat_found:
            # Update seats file
            with open(self.seats_file, 'w') as f:
                json.dump(updated_seats, f, indent=2, default=str)

            # Update organization seat count
            org = self.get_organization(organization_id)
            if org and org.seats_used > 0:
                org.seats_used -= 1
                org.updated_at = datetime.now()
                self._save_organization(org)

            return True

        return False

    def get_organization(self, organization_id: str) -> Optional[Organization]:
        """Get organization by ID"""
        organizations = self._load_organizations()
        for org_data in organizations:
            if org_data['id'] == organization_id:
                return Organization(**org_data)
        return None

    def get_organization_by_domain(self, domain: str) -> Optional[Organization]:
        """Get organization by domain"""
        organizations = self._load_organizations()
        for org_data in organizations:
            if org_data['domain'] == domain:
                return Organization(**org_data)
        return None

    def get_organization_seats(self, organization_id: str) -> List[SeatAssignment]:
        """Get all seat assignments for an organization"""
        seats = self._load_seat_assignments()
        return [
            SeatAssignment(**seat_data)
            for seat_data in seats
            if seat_data['organization_id'] == organization_id
        ]

    def record_usage(
        self,
        organization_id: str,
        scans: int = 0,
        api_calls: int = 0,
        detector_type: str = None,
        endpoint: str = None
    ) -> None:
        """Record usage for billing/analytics"""
        usage = self._load_usage()
        current_period = self._get_current_billing_period()

        # Find or create usage record
        usage_key = f"{organization_id}_{current_period.isoformat()}"
        if usage_key not in usage:
            usage[usage_key] = {
                'organization_id': organization_id,
                'period_start': current_period.isoformat(),
                'period_end': (current_period + timedelta(days=30)).isoformat(),
                'scans_total': 0,
                'scans_by_detector': {},
                'api_calls_total': 0,
                'api_calls_by_endpoint': {},
                'active_users': 0,
                'storage_used_gb': 0.0,
                'compliance_scans': 0,
                'custom_rules_used': 0,
                'federated_learning_sessions': 0
            }

        # Update usage
        usage_record = usage[usage_key]
        usage_record['scans_total'] += scans
        usage_record['api_calls_total'] += api_calls

        if detector_type:
            usage_record['scans_by_detector'][detector_type] = \
                usage_record['scans_by_detector'].get(detector_type, 0) + scans

        if endpoint:
            usage_record['api_calls_by_endpoint'][endpoint] = \
                usage_record['api_calls_by_endpoint'].get(endpoint, 0) + api_calls

        # Save updated usage
        with open(self.usage_file, 'w') as f:
            json.dump(usage, f, indent=2, default=str)

    def get_usage_report(self, organization_id: str, months: int = 3) -> List[EnterpriseUsage]:
        """Get usage report for organization"""
        usage = self._load_usage()
        reports = []

        for i in range(months):
            period_start = self._get_current_billing_period() - timedelta(days=30 * i)
            usage_key = f"{organization_id}_{period_start.isoformat()}"

            if usage_key in usage:
                usage_data = usage[usage_key]
                reports.append(EnterpriseUsage(**usage_data))

        return reports

    def check_limits(self, organization_id: str) -> Dict[str, Any]:
        """
        Check if organization is approaching or exceeding limits

        Returns:
            {
                'seats': {'used': int, 'allocated': int, 'status': 'ok|warning|exceeded'},
                'scans': {'used': int, 'limit': int, 'status': 'ok|warning|exceeded'},
                'api': {'used': int, 'limit': int, 'status': 'ok|warning|exceeded'}
            }
        """
        org = self.get_organization(organization_id)
        if not org:
            return {}

        # Get current usage
        usage_reports = self.get_usage_report(organization_id, months=1)
        current_usage = usage_reports[0] if usage_reports else None

        result = {}

        # Check seats
        seats_used = org.seats_used
        seats_allocated = org.seats_allocated
        seats_status = self._calculate_limit_status(seats_used, seats_allocated, 0.9)
        result['seats'] = {
            'used': seats_used,
            'allocated': seats_allocated,
            'status': seats_status
        }

        # Check scans
        scans_used = current_usage.scans_total if current_usage else 0
        scans_limit = org.monthly_scan_limit
        if scans_limit:
            scans_status = self._calculate_limit_status(scans_used, scans_limit, 0.8)
        else:
            scans_status = 'ok'  # Unlimited
        result['scans'] = {
            'used': scans_used,
            'limit': scans_limit,
            'status': scans_status
        }

        # Check API calls (rough estimate per hour)
        api_used = current_usage.api_calls_total if current_usage else 0
        api_limit = org.api_rate_limit * 24 * 30  # Daily rate * 30 days
        api_status = self._calculate_limit_status(api_used, api_limit, 0.8)
        result['api'] = {
            'used': api_used,
            'limit': api_limit,
            'status': api_status
        }

        return result

    def _calculate_limit_status(self, used: int, limit: Optional[int], warning_threshold: float) -> str:
        """Calculate limit status"""
        if limit is None:
            return 'ok'  # Unlimited

        if used >= limit:
            return 'exceeded'
        elif used >= limit * warning_threshold:
            return 'warning'
        else:
            return 'ok'

    def _generate_user_license_key(self, org_id: str, user_email: str, role: str) -> str:
        """Generate license key for a specific user"""
        import hashlib
        import hmac

        data = f"{org_id}:{user_email}:{role}:{int(time.time())}"
        secret = os.environ.get('PARRY_LICENSE_SECRET', 'enterprise-secret')
        signature = hmac.new(
            secret.encode(),
            data.encode(),
            hashlib.sha256
        ).hexdigest()

        return f"VALID8-ENT-{signature[:16].upper()}"

    def _get_current_billing_period(self) -> datetime:
        """Get start of current billing period (1st of month)"""
        now = datetime.now()
        return datetime(now.year, now.month, 1)

    def _save_organization(self, org: Organization) -> None:
        """Save organization to storage"""
        organizations = self._load_organizations()
        org_dict = asdict(org)

        # Update or add organization
        found = False
        for i, existing_org in enumerate(organizations):
            if existing_org['id'] == org.id:
                organizations[i] = org_dict
                found = True
                break

        if not found:
            organizations.append(org_dict)

        with open(self.organizations_file, 'w') as f:
            json.dump(organizations, f, indent=2, default=str)

    def _save_seat_assignment(self, seat: SeatAssignment) -> None:
        """Save seat assignment to storage"""
        seats = self._load_seat_assignments()
        seat_dict = asdict(seat)

        # Check if seat already exists (update)
        found = False
        for i, existing_seat in enumerate(seats):
            if existing_seat['organization_id'] == seat.organization_id and \
               existing_seat['user_email'] == seat.user_email:
                seats[i] = seat_dict
                found = True
                break

        if not found:
            seats.append(seat_dict)

        with open(self.seats_file, 'w') as f:
            json.dump(seats, f, indent=2, default=str)

    def _load_organizations(self) -> List[Dict]:
        """Load organizations from storage"""
        if not self.organizations_file.exists():
            return []
        try:
            with open(self.organizations_file, 'r') as f:
                return json.load(f)
        except:
            return []

    def _load_seat_assignments(self) -> List[Dict]:
        """Load seat assignments from storage"""
        if not self.seats_file.exists():
            return []
        try:
            with open(self.seats_file, 'r') as f:
                return json.load(f)
        except:
            return []

    def _load_usage(self) -> Dict:
        """Load usage data from storage"""
        if not self.usage_file.exists():
            return {}
        try:
            with open(self.usage_file, 'r') as f:
                return json.load(f)
        except:
            return {}


# Example usage and testing
if __name__ == '__main__':
    # Example: Create enterprise organization
    billing_manager = EnterpriseBillingManager()

    # Create Acme Corp organization
    org = billing_manager.create_organization(
        name="Acme Corp",
        domain="acme.com",
        admin_email="admin@acme.com",
        tier="enterprise",
        seats=50
    )

    print(f"Created organization: {org.name} (ID: {org.id})")
    print(f"Seats allocated: {org.seats_allocated}")
    print(f"Monthly scan limit: {org.monthly_scan_limit}")

    # Assign seats to team members
    seat1 = billing_manager.assign_seat(org.id, "developer1@acme.com", "John Developer", "developer")
    seat2 = billing_manager.assign_seat(org.id, "security@acme.com", "Jane Security", "auditor")

    print(f"Assigned seat to {seat1.user_email} (License: {seat1.license_key[:20]}...)")
    print(f"Assigned seat to {seat2.user_email} (License: {seat2.license_key[:20]}...)")

    # Record some usage
    billing_manager.record_usage(org.id, scans=1000, api_calls=500)

    # Check limits
    limits = billing_manager.check_limits(org.id)
    print(f"Organization limits: {limits}")
