const ethers = require('ethers');
const axios = require('axios');
const readline = require('readline');

class SuperintentAutoReferral {
    constructor() {
        this.baseUrl = 'https://bff-root.superintent.ai';
        this.walletConnectProjectId = 'ed0ac304e1fca7932c6090d955532a4e';
        this.questIds = [
            'zuaojk0ugeka9ue45t7mx6r8',
            'pr44jiu3cdnwscdi3dco3sc4'
        ];
    }

    generateWallet() {
        const wallet = ethers.Wallet.createRandom();
        return {
            address: wallet.address,
            privateKey: wallet.privateKey,
            mnemonic: wallet.mnemonic.phrase
        };
    }

    createSIWEMessage(address, nonce) {
        const domain = 'mission.superintent.ai';
        const uri = 'https://mission.superintent.ai';
        const version = '1';
        const chainId = '1';
        const issuedAt = new Date().toISOString();

        return `${domain} wants you to sign in with your Ethereum account:
${address}

To securely sign in, please sign this message to verify you're the owner of this wallet.

URI: ${uri}
Version: ${version}
Chain ID: ${chainId}
Nonce: ${nonce}
Issued At: ${issuedAt}`;
    }

    async signSIWEMessage(privateKey, message) {
        const wallet = new ethers.Wallet(privateKey);
        const signature = await wallet.signMessage(message);
        return signature;
    }

    getHeaders(cookies = null) {
        const headers = {
            'accept': 'application/json, text/plain, */*',
            'accept-encoding': 'gzip, deflate, br, zstd',
            'accept-language': 'en-US,en;q=0.9,id;q=0.8',
            'content-type': 'application/json',
            'origin': 'https://mission.superintent.ai',
            'referer': 'https://mission.superintent.ai/',
            'sec-ch-ua': '"Chromium";v="140", "Not=A?Brand";v="24", "Google Chrome";v="140"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-site',
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36'
        };

        if (cookies) {
            headers['cookie'] = cookies;
        }

        return headers;
    }

    parseCookies(setCookieHeaders) {
        if (!setCookieHeaders) return {};
        
        const cookies = {};
        const cookieArray = Array.isArray(setCookieHeaders) ? setCookieHeaders : [setCookieHeaders];
        
        cookieArray.forEach(cookie => {
            const parts = cookie.split(';')[0].split('=');
            if (parts.length === 2) {
                cookies[parts[0]] = parts[1];
            }
        });
        
        return cookies;
    }

    formatCookies(cookiesObj) {
        return Object.entries(cookiesObj)
            .map(([key, value]) => `${key}=${value}`)
            .join('; ');
    }

    async getNonce() {
        try {
            const response = await axios.get(`${this.baseUrl}/v1/auth/nonce`, {
                headers: this.getHeaders(),
                withCredentials: true
            });
            
            const cookies = this.parseCookies(response.headers['set-cookie']);
            
            return {
                nonce: response.data.nonce,
                cookies: cookies
            };
        } catch (error) {
            console.error('Error getting nonce:', error.response?.data || error.message);
            throw error;
        }
    }

    async authenticateWithSIWE(address, signature, message, initialCookies) {
        try {
            const cookieString = this.formatCookies(initialCookies);
            
            const response = await axios.post(`${this.baseUrl}/v1/auth/siwe`, {
                message,
                signature
            }, {
                headers: this.getHeaders(cookieString),
                withCredentials: true,
                validateStatus: function (status) {
                    return status >= 200 && status < 500;
                }
            });

            if (response.status === 401) {
                console.error('Authentication failed. Response:', response.data);
                throw new Error('Authentication failed with 401');
            }

            const newCookies = this.parseCookies(response.headers['set-cookie']);
            const allCookies = { ...initialCookies, ...newCookies };

            allCookies['l-addr'] = address;

            return allCookies;
        } catch (error) {
            if (error.response) {
                console.error('Auth error response:', error.response.status, error.response.data);
            }
            throw error;
        }
    }

    async validateReferral(referralCode, cookies) {
        try {
            const cookieString = this.formatCookies(cookies);
            
            const response = await axios.post(`${this.baseUrl}/v1/me/referral/validate`, {
                referralCode
            }, {
                headers: this.getHeaders(cookieString)
            });
            
            return response.data.success;
        } catch (error) {
            console.error('Error validating referral:', error.response?.data || error.message);
            return false;
        }
    }

    async bindReferral(referralCode, cookies) {
        try {
            const cookieString = this.formatCookies(cookies);
            
            const response = await axios.post(`${this.baseUrl}/v1/me/referral/bind`, {
                referralCode
            }, {
                headers: this.getHeaders(cookieString)
            });
            
            return response.data.success;
        } catch (error) {
            console.error('Error binding referral:', error.response?.data || error.message);
            return false;
        }
    }

    async completeOnboarding(cookies) {
        try {
            const cookieString = this.formatCookies(cookies);
            
            const response = await axios.post(`${this.baseUrl}/v1/onboarding/complete`, {
                signal: {}
            }, {
                headers: this.getHeaders(cookieString)
            });
            
            return response.data;
        } catch (error) {
            console.error('Error completing onboarding:', error.response?.data || error.message);
            return null;
        }
    }

    async verifyQuests(cookies) {
        const results = [];
        const cookieString = this.formatCookies(cookies);
        
        for (const questId of this.questIds) {
            try {
                const response = await axios.post(`${this.baseUrl}/v1/quests/verify`, {
                    id: questId
                }, {
                    headers: this.getHeaders(cookieString)
                });

                if (response.data.success) {
                    results.push({
                        questId,
                        points: response.data.pointsGranted,
                        success: true
                    });
                    console.log(`  Quest ${questId}: +${response.data.pointsGranted} points`);
                }
            } catch (error) {
                console.error(`  Quest ${questId}: Failed - ${error.response?.data?.message || error.message}`);
                results.push({
                    questId,
                    points: 0,
                    success: false
                });
            }
            
            await this.sleep(1000);
        }
        
        return results;
    }

    async processAccount(referralCode, accountNumber) {
        console.log(`\n[Account ${accountNumber}] Starting registration...`);

        try {
            const wallet = this.generateWallet();
            console.log(`[Account ${accountNumber}] Generated wallet: ${wallet.address}`);

            const nonceData = await this.getNonce();
            console.log(`[Account ${accountNumber}] Got nonce: ${nonceData.nonce}`);
            console.log(`[Account ${accountNumber}] Initial cookies:`, Object.keys(nonceData.cookies));

            const message = this.createSIWEMessage(wallet.address, nonceData.nonce);
            const signature = await this.signSIWEMessage(wallet.privateKey, message);
            console.log(`[Account ${accountNumber}] Signed message`);
            console.log(`[Account ${accountNumber}] Signature: ${signature.substring(0, 20)}...`);

            const cookies = await this.authenticateWithSIWE(
                wallet.address, 
                signature, 
                message,
                nonceData.cookies
            );
            
            if (!cookies.si_token) {
                throw new Error('Failed to get authentication token');
            }
            console.log(`[Account ${accountNumber}] Authenticated successfully`);
            console.log(`[Account ${accountNumber}] All cookies:`, Object.keys(cookies));

            const isValidReferral = await this.validateReferral(referralCode, cookies);
            if (!isValidReferral) {
                console.log(`[Account ${accountNumber}] Warning: Referral validation failed`);
            }

            const isReferralBound = await this.bindReferral(referralCode, cookies);
            if (!isReferralBound) {
                console.log(`[Account ${accountNumber}] Warning: Referral binding failed`);
            } else {
                console.log(`[Account ${accountNumber}] Referral bound successfully`);
            }

            const onboardingResult = await this.completeOnboarding(cookies);
            if (onboardingResult) {
                console.log(`[Account ${accountNumber}] Onboarding completed`);
            }

            console.log(`[Account ${accountNumber}] Verifying quests...`);
            const questResults = await this.verifyQuests(cookies);
            const totalPoints = questResults.reduce((sum, quest) => sum + quest.points, 0);
            console.log(`[Account ${accountNumber}] Total points earned: ${totalPoints}`);

            return {
                accountNumber,
                wallet,
                success: true,
                totalPoints,
                referralBound: isReferralBound,
                questResults
            };

        } catch (error) {
            console.error(`[Account ${accountNumber}] Error:`, error.message);
            return {
                accountNumber,
                wallet: null,
                success: false,
                error: error.message
            };
        }
    }

    async processMultipleAccounts(referralCode, numberOfAccounts) {
        console.log(`\nStarting auto referral process...`);
        console.log(`Referral Code: ${referralCode}`);
        console.log(`Number of Accounts: ${numberOfAccounts}`);
        console.log('='.repeat(50));

        const results = [];

        for (let i = 1; i <= numberOfAccounts; i++) {
            const result = await this.processAccount(referralCode, i);
            results.push(result);

            if (i < numberOfAccounts) {
                console.log(`\nWaiting 5 seconds before next account...`);
                await this.sleep(5000);
            }
        }

        this.printSummary(results);

        return results;
    }

    sleep(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    printSummary(results) {
        console.log('\n' + '='.repeat(50));
        console.log('SUMMARY REPORT');
        console.log('='.repeat(50));

        const successful = results.filter(r => r.success);
        const failed = results.filter(r => !r.success);

        console.log(`Total Accounts Processed: ${results.length}`);
        console.log(`Successful: ${successful.length}`);
        console.log(`Failed: ${failed.length}`);

        const totalPoints = successful.reduce((sum, r) => sum + (r.totalPoints || 0), 0);
        console.log(`Total Points Earned: ${totalPoints}`);

        if (successful.length > 0) {
            console.log('\nSuccessful Accounts:');
            successful.forEach(result => {
                console.log(`  Account ${result.accountNumber}: ${result.wallet.address} - ${result.totalPoints} points`);
            });
        }

        if (failed.length > 0) {
            console.log('\nFailed Accounts:');
            failed.forEach(result => {
                console.log(`  Account ${result.accountNumber}: ${result.error}`);
            });
        }

        this.saveResultsToFile(results);
    }

    saveResultsToFile(results) {
        const fs = require('fs');

        let csvContent = 'Account,Address,Private Key,Mnemonic,Success,Points,Referral Bound,Error\n';

        results.forEach(result => {
            if (result.success && result.wallet) {
                csvContent += `${result.accountNumber},"${result.wallet.address}","${result.wallet.privateKey}","${result.wallet.mnemonic}",${result.success},${result.totalPoints},${result.referralBound},""\n`;
            } else {
                csvContent += `${result.accountNumber},"","","",${result.success},0,false,"${result.error || 'Unknown error'}"\n`;
            }
        });

        const filename = `superintent_results_${new Date().toISOString().slice(0, 19).replace(/:/g, '-')}.csv`;
        fs.writeFileSync(filename, csvContent);
        console.log(`\nResults saved to: ${filename}`);
    }
}

async function main() {
    const rl = readline.createInterface({
        input: process.stdin,
        output: process.stdout
    });

    const question = (prompt) => {
        return new Promise((resolve) => {
            rl.question(prompt, resolve);
        });
    };

    try {
        console.log('='.repeat(50));
        console.log('SUPERINTENT AUTO REFERRAL @ByDontol');
        console.log('='.repeat(50));

        const referralCode = await question('Enter referral code: ');
        const numberOfAccounts = parseInt(await question('Enter number of accounts to create: '));

        if (!referralCode.trim()) {
            console.log('Error: Referral code cannot be empty');
            return;
        }

        if (isNaN(numberOfAccounts) || numberOfAccounts <= 0) {
            console.log('Error: Number of accounts must be a positive integer');
            return;
        }

        const autoReferral = new SuperintentAutoReferral();
        await autoReferral.processMultipleAccounts(referralCode.trim(), numberOfAccounts);

    } catch (error) {
        console.error('Main error:', error.message);
    } finally {
        rl.close();
    }
}

if (typeof module !== 'undefined' && module.exports) {
    module.exports = SuperintentAutoReferral;
}

if (require.main === module) {
    main();
}
