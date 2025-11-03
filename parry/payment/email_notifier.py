#!/usr/bin/env python3
# Copyright (c) 2025 Parry Security Labs
# SPDX-License-Identifier: MIT

"""
Email notification system for Parry payments

Supports SendGrid and AWS SES for sending transactional emails.
"""

import os
from typing import Dict, Any, Optional
from dataclasses import dataclass
from datetime import datetime

try:
    from sendgrid import SendGridAPIClient
    from sendgrid.helpers.mail import Mail, Email, To, Content
    SENDGRID_AVAILABLE = True
except ImportError:
    SENDGRID_AVAILABLE = False

try:
    import boto3
    from botocore.exceptions import ClientError
    AWS_SES_AVAILABLE = True
except ImportError:
    AWS_SES_AVAILABLE = False


@dataclass
class EmailConfig:
    """Email configuration"""
    SENDGRID_API_KEY: str = os.environ.get('SENDGRID_API_KEY', '')
    AWS_SES_REGION: str = os.environ.get('AWS_SES_REGION', 'us-east-1')
    FROM_EMAIL: str = os.environ.get('PARRY_FROM_EMAIL', 'noreply@parryscanner.com')
    FROM_NAME: str = 'Parry Security Labs'
    SUPPORT_EMAIL: str = 'support@parryscanner.com'


class EmailNotifier:
    """Send transactional emails"""
    
    def __init__(self, provider: str = 'sendgrid'):
        """
        Initialize email notifier
        
        Args:
            provider: 'sendgrid' or 'aws_ses'
        """
        self.provider = provider
        self.config = EmailConfig()
        
        if provider == 'sendgrid' and not SENDGRID_AVAILABLE:
            raise RuntimeError("SendGrid not installed. Run: pip install sendgrid")
        
        if provider == 'aws_ses' and not AWS_SES_AVAILABLE:
            raise RuntimeError("Boto3 not installed. Run: pip install boto3")
        
        if provider == 'sendgrid':
            self.client = SendGridAPIClient(self.config.SENDGRID_API_KEY)
        elif provider == 'aws_ses':
            self.client = boto3.client('ses', region_name=self.config.AWS_SES_REGION)
    
    def send_license_email(
        self,
        to_email: str,
        to_name: str,
        license_key: str,
        tier: str,
        expires: datetime,
        metadata: Dict[str, Any] = None
    ) -> bool:
        """
        Send license activation email
        
        Args:
            to_email: Recipient email
            to_name: Recipient name
            license_key: Generated license key
            tier: 'pro' or 'enterprise'
            expires: License expiration date
            metadata: Additional metadata (subscription ID, etc.)
        
        Returns:
            True if sent successfully
        """
        subject = f"Your Parry Scanner {tier.title()} License"
        
        html_content = self._generate_license_email_html(
            to_name, license_key, tier, expires, metadata
        )
        
        text_content = self._generate_license_email_text(
            to_name, license_key, tier, expires, metadata
        )
        
        return self._send_email(to_email, subject, html_content, text_content)
    
    def send_payment_failed_email(
        self,
        to_email: str,
        to_name: str,
        tier: str,
        amount: float,
        reason: str
    ) -> bool:
        """Send payment failure notification"""
        subject = "Payment Failed - Action Required"
        
        html_content = f"""
        <html>
        <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
            <h2 style="color: #d32f2f;">Payment Failed</h2>
            
            <p>Hi {to_name},</p>
            
            <p>We were unable to process your payment for <strong>Parry Scanner {tier.title()}</strong>.</p>
            
            <div style="background: #fff3e0; padding: 15px; border-left: 4px solid #ff9800; margin: 20px 0;">
                <strong>Amount:</strong> ${amount:.2f}<br>
                <strong>Reason:</strong> {reason}
            </div>
            
            <p>Please update your payment method to continue using Parry Scanner {tier.title()}:</p>
            
            <p style="margin: 30px 0;">
                <a href="https://parryscanner.com/billing" 
                   style="background: #1976d2; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px;">
                    Update Payment Method
                </a>
            </p>
            
            <p>If you have questions, contact us at <a href="mailto:{self.config.SUPPORT_EMAIL}">{self.config.SUPPORT_EMAIL}</a></p>
            
            <hr style="margin: 30px 0; border: none; border-top: 1px solid #eee;">
            <p style="color: #666; font-size: 12px;">Parry Security Labs</p>
        </body>
        </html>
        """
        
        text_content = f"""
Payment Failed

Hi {to_name},

We were unable to process your payment for Parry Scanner {tier.title()}.

Amount: ${amount:.2f}
Reason: {reason}

Please update your payment method to continue using Parry Scanner:
https://parryscanner.com/billing

Questions? Contact {self.config.SUPPORT_EMAIL}

Parry Security Labs
        """
        
        return self._send_email(to_email, subject, html_content, text_content)
    
    def send_subscription_cancelled_email(
        self,
        to_email: str,
        to_name: str,
        tier: str,
        expires: datetime
    ) -> bool:
        """Send subscription cancellation confirmation"""
        subject = "Subscription Cancelled"
        
        html_content = f"""
        <html>
        <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
            <h2>Subscription Cancelled</h2>
            
            <p>Hi {to_name},</p>
            
            <p>Your Parry Scanner {tier.title()} subscription has been cancelled.</p>
            
            <div style="background: #e3f2fd; padding: 15px; border-left: 4px solid #2196f3; margin: 20px 0;">
                You'll continue to have access until <strong>{expires.strftime('%B %d, %Y')}</strong>
            </div>
            
            <p>After this date, your account will revert to the free tier with:</p>
            <ul>
                <li>Local Ollama support only</li>
                <li>100 file scan limit</li>
                <li>30+ basic detectors</li>
            </ul>
            
            <p>Want to keep your {tier.title()} features? Reactivate anytime:</p>
            
            <p style="margin: 30px 0;">
                <a href="https://parryscanner.com/subscribe" 
                   style="background: #1976d2; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px;">
                    Reactivate Subscription
                </a>
            </p>
            
            <p>We're sad to see you go! If you have feedback, we'd love to hear it at <a href="mailto:{self.config.SUPPORT_EMAIL}">{self.config.SUPPORT_EMAIL}</a></p>
            
            <hr style="margin: 30px 0; border: none; border-top: 1px solid #eee;">
            <p style="color: #666; font-size: 12px;">Parry Security Labs</p>
        </body>
        </html>
        """
        
        text_content = f"""
Subscription Cancelled

Hi {to_name},

Your Parry Scanner {tier.title()} subscription has been cancelled.

You'll continue to have access until {expires.strftime('%B %d, %Y')}.

After this date, your account will revert to the free tier.

Want to reactivate? Visit: https://parryscanner.com/subscribe

Feedback? Contact {self.config.SUPPORT_EMAIL}

Parry Security Labs
        """
        
        return self._send_email(to_email, subject, html_content, text_content)
    
    def _generate_license_email_html(
        self,
        to_name: str,
        license_key: str,
        tier: str,
        expires: datetime,
        metadata: Dict[str, Any]
    ) -> str:
        """Generate HTML content for license email"""
        features = {
            'pro': [
                'Hosted LLM (GPT-4, Claude, Gemini)',
                'Unlimited file scanning',
                '150+ advanced detectors',
                'VS Code & JetBrains extensions',
                'Email support'
            ],
            'enterprise': [
                'Everything in Pro',
                'REST API access (500 scans/day)',
                'SSO integration',
                'On-premise deployment',
                'Priority support',
                'Custom detectors'
            ]
        }
        
        feature_list = features.get(tier, [])
        feature_html = ''.join([f'<li>{f}</li>' for f in feature_list])
        
        return f"""
        <html>
        <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
            <h2 style="color: #1976d2;">Welcome to Parry Scanner {tier.title()}!</h2>
            
            <p>Hi {to_name},</p>
            
            <p>Thank you for subscribing! Your license is ready to use.</p>
            
            <div style="background: #f5f5f5; padding: 20px; border-radius: 4px; margin: 20px 0;">
                <strong>Your License Key:</strong><br>
                <code style="font-size: 14px; background: white; padding: 10px; display: block; margin-top: 10px; border: 1px solid #ddd; border-radius: 4px;">
                    {license_key}
                </code>
            </div>
            
            <p><strong>Activation Instructions:</strong></p>
            <ol>
                <li>Install Parry Scanner: <code>pip install parry-scanner</code></li>
                <li>Activate your license: <code>parry activate {license_key}</code></li>
                <li>Start scanning: <code>parry scan /path/to/project</code></li>
            </ol>
            
            <p><strong>What's Included:</strong></p>
            <ul>{feature_html}</ul>
            
            <p><strong>License Details:</strong></p>
            <ul>
                <li>Tier: {tier.title()}</li>
                <li>Expires: {expires.strftime('%B %d, %Y')}</li>
                <li>Subscription: Auto-renewing</li>
            </ul>
            
            <hr style="margin: 30px 0; border: none; border-top: 1px solid #eee;">
            
            <p><strong>Need Help?</strong></p>
            <ul>
                <li>Documentation: <a href="https://parryscanner.com/docs">parryscanner.com/docs</a></li>
                <li>Support: <a href="mailto:{self.config.SUPPORT_EMAIL}">{self.config.SUPPORT_EMAIL}</a></li>
                <li>Billing: <a href="https://parryscanner.com/billing">parryscanner.com/billing</a></li>
            </ul>
            
            <p>Happy scanning!</p>
            
            <hr style="margin: 30px 0; border: none; border-top: 1px solid #eee;">
            <p style="color: #666; font-size: 12px;">Parry Security Labs</p>
        </body>
        </html>
        """
    
    def _generate_license_email_text(
        self,
        to_name: str,
        license_key: str,
        tier: str,
        expires: datetime,
        metadata: Dict[str, Any]
    ) -> str:
        """Generate plain text content for license email"""
        return f"""
Welcome to Parry Scanner {tier.title()}!

Hi {to_name},

Thank you for subscribing! Your license is ready to use.

YOUR LICENSE KEY:
{license_key}

ACTIVATION INSTRUCTIONS:
1. Install Parry Scanner: pip install parry-scanner
2. Activate your license: parry activate {license_key}
3. Start scanning: parry scan /path/to/project

LICENSE DETAILS:
- Tier: {tier.title()}
- Expires: {expires.strftime('%B %d, %Y')}
- Subscription: Auto-renewing

NEED HELP?
- Documentation: https://parryscanner.com/docs
- Support: {self.config.SUPPORT_EMAIL}
- Billing: https://parryscanner.com/billing

Happy scanning!

Parry Security Labs
        """
    
    def _send_email(
        self,
        to_email: str,
        subject: str,
        html_content: str,
        text_content: str
    ) -> bool:
        """Send email via configured provider"""
        try:
            if self.provider == 'sendgrid':
                return self._send_via_sendgrid(to_email, subject, html_content, text_content)
            elif self.provider == 'aws_ses':
                return self._send_via_ses(to_email, subject, html_content, text_content)
            else:
                raise ValueError(f"Unknown email provider: {self.provider}")
        except Exception as e:
            print(f"Error sending email: {e}")
            return False
    
    def _send_via_sendgrid(
        self,
        to_email: str,
        subject: str,
        html_content: str,
        text_content: str
    ) -> bool:
        """Send via SendGrid"""
        message = Mail(
            from_email=Email(self.config.FROM_EMAIL, self.config.FROM_NAME),
            to_emails=To(to_email),
            subject=subject,
            plain_text_content=Content("text/plain", text_content),
            html_content=Content("text/html", html_content)
        )
        
        response = self.client.send(message)
        return response.status_code == 202
    
    def _send_via_ses(
        self,
        to_email: str,
        subject: str,
        html_content: str,
        text_content: str
    ) -> bool:
        """Send via AWS SES"""
        try:
            response = self.client.send_email(
                Source=f'{self.config.FROM_NAME} <{self.config.FROM_EMAIL}>',
                Destination={'ToAddresses': [to_email]},
                Message={
                    'Subject': {'Data': subject, 'Charset': 'UTF-8'},
                    'Body': {
                        'Text': {'Data': text_content, 'Charset': 'UTF-8'},
                        'Html': {'Data': html_content, 'Charset': 'UTF-8'}
                    }
                }
            )
            return True
        except ClientError as e:
            print(f"SES error: {e.response['Error']['Message']}")
            return False
