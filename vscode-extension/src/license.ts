// Parry (C) by Lemonade Stand. Written by Andy Kurapati and Shreyan Mitra
/**
 * License Manager - Handles Pro/Enterprise license validation
 */

import * as vscode from 'vscode';
import axios from 'axios';

interface LicenseInfo {
    tier: 'free' | 'pro' | 'enterprise';
    llm_mode: 'local' | 'hosted';
    file_limit: number | null;
    license_key?: string;
}

export class LicenseManager {
    private context: vscode.ExtensionContext;
    
    constructor(context: vscode.ExtensionContext) {
        this.context = context;
    }
    
    getLicenseInfo(): LicenseInfo {
        const licenseKey = this.context.globalState.get<string>('parryLicenseKey');
        
        if (!licenseKey) {
            // Free tier
            return {
                tier: 'free',
                llm_mode: 'local',
                file_limit: 100
            };
        }
        
        // Decode license (simplified - real implementation would validate with API)
        const tier = this.context.globalState.get<string>('parryTier', 'free') as 'free' | 'pro' | 'enterprise';
        
        return {
            tier,
            llm_mode: tier === 'free' ? 'local' : 'hosted',
            file_limit: tier === 'free' ? 100 : null,
            license_key: licenseKey
        };
    }
    
    async activateLicense(licenseKey: string): Promise<boolean> {
        try {
            // Validate license with Parry API
            const response = await axios.post('https://api.parry.dev/license/validate', {
                license_key: licenseKey
            }, {
                timeout: 10000
            });
            
            if (response.data.valid) {
                await this.context.globalState.update('parryLicenseKey', licenseKey);
                await this.context.globalState.update('parryTier', response.data.tier);
                await this.context.globalState.update('parryExpires', response.data.expires);
                return true;
            }
            
            return false;
        } catch (error) {
            console.error('License validation failed:', error);
            return false;
        }
    }
    
    async clearLicense() {
        await this.context.globalState.update('parryLicenseKey', undefined);
        await this.context.globalState.update('parryTier', 'free');
        await this.context.globalState.update('parryExpires', undefined);
    }
}
