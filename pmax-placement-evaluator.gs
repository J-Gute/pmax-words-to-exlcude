/**
 * Enhanced Performance Max Placement Quality Assessment Script
 * @version 5.7
 */

// Configuration
const SPREADSHEET_URL = 'URL Here';
const LOOKBACK_WINDOW = 10;
const MIN_IMPRESSIONS = 3;
const URL_TIMEOUT_SECONDS = 30;
const DNS_TIMEOUT_SECONDS = 5;

// Auto-exclusion configuration
const ADD_TO_ACCOUNT_EXCLUSIONS = true; // Set to false to disable automatic account-level exclusions
const AUTO_EXCLUSION_THRESHOLD = 0.2; // Add to exclusions if score falls below this threshold
const DRY_RUN_MODE = true; // Set to true to see what would be excluded without actually excluding

const QUALITY_LABELS = {
    HIGH_QUALITY: 'LIKELY KEEP',
    MEDIUM_QUALITY: 'LIKELY EXCLUDE', 
    LOW_QUALITY: 'EXCLUDE'
};

const QUALITY_THRESHOLDS = {
    HIGH_QUALITY: 0.85,
    MEDIUM_QUALITY: 0.55,
    LOW_QUALITY: 0.55
};

/**
 * Cache Manager for External Data
 */
class CacheManager {
    constructor() {
        this.cache = PropertiesService.getScriptProperties();
        this.cacheExpiryHours = 24 * 14; // 2 weeks
    }

    getCachedData(key) {
        try {
            const cachedItem = this.cache.getProperty(key);
            if (!cachedItem) return null;
            
            const parsed = JSON.parse(cachedItem);
            const now = new Date().getTime();
            
            if (now - parsed.timestamp > this.cacheExpiryHours * 60 * 60 * 1000) {
                this.cache.deleteProperty(key);
                return null;
            }
            
            return parsed.data;
        } catch (error) {
            console.log(`Cache read error for ${key}: ${error.message}`);
            return null;
        }
    }

    setCachedData(key, data) {
        try {
            const cacheItem = {
                data: data,
                timestamp: new Date().getTime()
            };
            this.cache.setProperty(key, JSON.stringify(cacheItem));
        } catch (error) {
            console.log(`Cache write error for ${key}: ${error.message}`);
        }
    }

    shouldRefreshCache(key) {
        return this.getCachedData(key) === null;
    }
}

/**
 * Account Exclusion Manager
 */
class AccountExclusionManager {
    constructor() {
        this.excludedDomains = [];
        this.exclusionErrors = [];
        this.exclusionStats = {
            attempted: 0,
            successful: 0,
            failed: 0,
            skipped: 0
        };
    }

    async addAccountLevelExclusions(placementsToExclude) {
        if (!ADD_TO_ACCOUNT_EXCLUSIONS) {
            console.log('Account-level exclusions disabled');
            return;
        }

        console.log(`Processing ${placementsToExclude.length} placements for account-level exclusion...`);

        for (const placement of placementsToExclude) {
            try {
                this.exclusionStats.attempted++;

                if (placement.placementType !== 'WEBSITE' || !placement.targetUrl) {
                    this.exclusionStats.skipped++;
                    continue;
                }

                const domain = this.extractDomain(placement.targetUrl);
                if (!domain || domain === 'unknown-domain') {
                    this.exclusionStats.skipped++;
                    continue;
                }

                if (DRY_RUN_MODE) {
                    console.log(`[DRY RUN] Would exclude: ${domain}`);
                    this.excludedDomains.push({
                        domain: domain,
                        reason: placement.reason,
                        score: placement.score,
                        status: 'DRY_RUN'
                    });
                    this.exclusionStats.successful++;
                } else {
                    const success = await this.addSingleExclusion(domain, placement);
                    if (success) {
                        this.excludedDomains.push({
                            domain: domain,
                            reason: placement.reason,
                            score: placement.score,
                            status: 'EXCLUDED'
                        });
                        this.exclusionStats.successful++;
                        console.log(`✓ Excluded: ${domain}`);
                    } else {
                        this.exclusionStats.failed++;
                    }
                }

                Utilities.sleep(100); // Rate limiting
            } catch (error) {
                this.exclusionStats.failed++;
                this.exclusionErrors.push({
                    placement: placement.targetUrl,
                    error: error.message
                });
                console.error(`Error excluding ${placement.targetUrl}: ${error.message}`);
            }
        }

        this.logExclusionSummary();
    }

    async addSingleExclusion(domain, placement) {
        try {
            // Add exclusion to all Performance Max campaigns
            const campaigns = AdsApp.campaigns()
                .withCondition('campaign.advertising_channel_type = PERFORMANCE_MAX')
                .withCondition('campaign.status = ENABLED')
                .get();

            let exclusionAdded = false;

            while (campaigns.hasNext()) {
                const campaign = campaigns.next();
                
                try {
                    const excludedPlacementOperation = campaign
                        .targeting()
                        .excludedPlacements()
                        .newExcludedPlacementBuilder()
                        .withUrl(domain)
                        .build();

                    if (excludedPlacementOperation.isSuccessful()) {
                        exclusionAdded = true;
                    }
                } catch (campaignError) {
                    console.log(`Failed to add exclusion to campaign ${campaign.getName()}: ${campaignError.message}`);
                }
            }

            return exclusionAdded;
        } catch (error) {
            console.error(`Exclusion failed for ${domain}: ${error.message}`);
            return false;
        }
    }

    extractDomain(url) {
        try {
            if (!url) return null;
            
            let cleanUrl = url.trim();
            if (!cleanUrl.match(/^https?:\/\//i)) {
                cleanUrl = 'https://' + cleanUrl;
            }
            
            const urlObj = new URL(cleanUrl);
            return urlObj.hostname.toLowerCase().replace(/^www\./, '');
        } catch (error) {
            const match = url.match(/(?:https?:\/\/)?(?:www\.)?([^\/?#]+)/i);
            return match ? match[1].toLowerCase() : null;
        }
    }

    logExclusionSummary() {
        console.log('\n=== EXCLUSION SUMMARY ===');
        console.log(`Mode: ${DRY_RUN_MODE ? 'DRY RUN' : 'LIVE'}`);
        console.log(`Attempted: ${this.exclusionStats.attempted}`);
        console.log(`Successful: ${this.exclusionStats.successful}`);
        console.log(`Failed: ${this.exclusionStats.failed}`);
        console.log(`Skipped: ${this.exclusionStats.skipped}`);
        
        if (this.exclusionErrors.length > 0) {
            console.log('\nErrors:');
            this.exclusionErrors.forEach(error => {
                console.log(`- ${error.placement}: ${error.error}`);
            });
        }
    }

    getExclusionResults() {
        return {
            excludedDomains: this.excludedDomains,
            stats: this.exclusionStats,
            errors: this.exclusionErrors
        };
    }
}

/**
 * Enhanced Blocklist Manager Class with IP Blacklist Support and Caching
 */
class BlocklistManager {
    constructor() {
        this.blockedDomains = new Set();
        this.blockedIPs = new Set();
        this.lastFetched = null;
        this.fetchSuccess = false;
        this.cacheManager = new CacheManager();
        this.blocklistSources = [
            'https://raw.githubusercontent.com/cbuijs/accomplist/main/easylist/optimized.black.domain.list',
            'https://raw.githubusercontent.com/cbuijs/accomplist/main/adult-themed/plain.black.domain.level-3.list',
            'https://raw.githubusercontent.com/cbuijs/accomplist/main/adult-themed/plain.black.domain.level-4.list',
            'https://raw.githubusercontent.com/cbuijs/accomplist/main/crypto/optimized.black.domain.list',
            'https://raw.githubusercontent.com/cbuijs/accomplist/main/gambling/optimized.black.domain.list',
            'https://raw.githubusercontent.com/cbuijs/accomplist/main/games/optimized.black.domain.list',
            'https://raw.githubusercontent.com/cbuijs/accomplist/main/malicious-dom/optimized.black.idn.domain.list',
            'https://raw.githubusercontent.com/cbuijs/accomplist/main/streaming/optimized.black.domain.list'
        ];
        this.ipBlocklistSource = 'https://raw.githubusercontent.com/cbuijs/accomplist/refs/heads/main/malicious-ip/plain.black.ipcidr.list';
        this.fetchResults = {};
    }

    async fetchBlocklist() {
        // Try to load from cache first
        const cachedDomains = this.cacheManager.getCachedData('blocklist_domains');
        const cachedIPs = this.cacheManager.getCachedData('blocklist_ips');
        
        if (cachedDomains && cachedIPs) {
            console.log('Loading blocklist from cache...');
            this.blockedDomains = new Set(cachedDomains);
            this.blockedIPs = new Set(cachedIPs);
            this.fetchSuccess = true;
            this.lastFetched = new Date();
            console.log(`Cached blocklist loaded: ${this.blockedDomains.size} domains, ${this.blockedIPs.size} IPs`);
            return { 
                success: this.fetchSuccess, 
                totalDomains: this.blockedDomains.size, 
                totalIPs: this.blockedIPs.size,
                fetchResults: {} 
            };
        }

        console.log('Fetching external blocklists...');
        const allDomains = new Set();
        const allIPs = new Set();
        let successfulFetches = 0;
        
        // Fetch domain blocklists
        for (const url of this.blocklistSources) {
            try {
                const response = UrlFetchApp.fetch(url, {
                    method: 'GET',
                    headers: { 'User-Agent': 'Mozilla/5.0 (compatible; GoogleAdsBot/1.0)' },
                    muteHttpExceptions: true
                });

                if (response.getResponseCode() === 200) {
                    const domains = response.getContentText()
                        .split('\n')
                        .map(line => line.trim())
                        .filter(line => line && !line.startsWith('#') && !line.startsWith('!') && line.includes('.'))
                        .map(domain => domain.toLowerCase());

                    domains.forEach(domain => allDomains.add(domain));
                    this.fetchResults[url] = { success: true, count: domains.length, error: null };
                    successfulFetches++;
                } else {
                    throw new Error(`HTTP ${response.getResponseCode()}`);
                }
            } catch (error) {
                console.log(`Failed to fetch ${url}: ${error.message}`);
                this.fetchResults[url] = { success: false, count: 0, error: error.message };
            }
        }

        // Fetch IP blocklist
        try {
            const response = UrlFetchApp.fetch(this.ipBlocklistSource, {
                method: 'GET',
                headers: { 'User-Agent': 'Mozilla/5.0 (compatible; GoogleAdsBot/1.0)' },
                muteHttpExceptions: true
            });

            if (response.getResponseCode() === 200) {
                const ips = response.getContentText()
                    .split('\n')
                    .map(line => line.trim())
                    .filter(line => line && !line.startsWith('#') && (line.includes('.') || line.includes(':')));

                ips.forEach(ip => allIPs.add(ip));
                this.fetchResults[this.ipBlocklistSource] = { success: true, count: ips.length, error: null };
                successfulFetches++;
            } else {
                throw new Error(`HTTP ${response.getResponseCode()}`);
            }
        } catch (error) {
            console.log(`Failed to fetch IP blocklist: ${error.message}`);
            this.fetchResults[this.ipBlocklistSource] = { success: false, count: 0, error: error.message };
        }

        this.blockedDomains = allDomains;
        this.blockedIPs = allIPs;
        this.lastFetched = new Date();
        this.fetchSuccess = successfulFetches > 0;

        if (successfulFetches === 0) {
            this.initializeFallbackBlocklist();
        } else {
            // Cache the results
            this.cacheManager.setCachedData('blocklist_domains', Array.from(this.blockedDomains));
            this.cacheManager.setCachedData('blocklist_ips', Array.from(this.blockedIPs));
        }
        
        console.log(`Blocklist loaded: ${this.blockedDomains.size} domains, ${this.blockedIPs.size} IPs from ${successfulFetches}/${this.blocklistSources.length + 1} sources`);
        return { 
            success: this.fetchSuccess, 
            totalDomains: this.blockedDomains.size, 
            totalIPs: this.blockedIPs.size,
            fetchResults: this.fetchResults 
        };
    }

    initializeFallbackBlocklist() {
        const fallbackDomains = [
            'doubleclick.net', 'googleadservices.com', 'googlesyndication.com',
            'facebook.com', 'instagram.com', 'twitter.com', 'tiktok.com', 'youtube.com',
            'pornhub.com', 'xvideos.com', 'bet365.com', 'pokerstars.com', 'coinbase.com'
        ];
        this.blockedDomains = new Set(fallbackDomains);
        this.blockedIPs = new Set(); // No fallback IPs
        console.log(`Using fallback blocklist: ${this.blockedDomains.size} domains`);
    }

    isDomainBlocked(domain) {
        if (!domain) return false;
        const cleanDomain = domain.toLowerCase().replace(/^www\./, '');
        
        if (this.blockedDomains.has(cleanDomain)) return true;
        
        for (const blockedDomain of this.blockedDomains) {
            if (cleanDomain.endsWith('.' + blockedDomain) || cleanDomain === blockedDomain) {
                return true;
            }
        }
        return false;
    }

    isIPBlocked(ip) {
        if (!ip) return false;
        
        // Direct IP match
        if (this.blockedIPs.has(ip) || this.blockedIPs.has(`${ip}/32`)) return true;
        
        // Check CIDR ranges (simplified check for common cases)
        for (const blockedIP of this.blockedIPs) {
            if (blockedIP.includes('/')) {
                const [network, prefix] = blockedIP.split('/');
                if (ip.startsWith(network.split('.').slice(0, Math.floor(parseInt(prefix) / 8)).join('.'))) {
                    return true;
                }
            }
        }
        return false;
    }

    getBlocklistStats() {
        return {
            totalDomains: this.blockedDomains.size,
            totalIPs: this.blockedIPs.size,
            lastFetched: this.lastFetched,
            fetchSuccess: this.fetchSuccess,
            fetchResults: this.fetchResults
        };
    }

    shouldRefreshBlocklist() {
        return this.cacheManager.shouldRefreshCache('blocklist_domains');
    }
}

class KeywordConfiguration {
    constructor() {
        this.initializeB2BIndustrialTerms();
        this.initializeWhitelistedDomains();
        this.initializeProfessionalDomains();
        this.SUSPICIOUS_TLDS = null; // Will be loaded async
        this.SPAM_KEYWORDS = null; // Will be loaded from external source
        this.cacheManager = new CacheManager();
        this.spamKeywordsSource = 'https://raw.githubusercontent.com/J-Gute/pmax-words-to-exlcude/main/spam-and-irrelevant-terms';
    }

    async initializeSpamKeywords() {
        // Try to load from cache first
        const cachedKeywords = this.cacheManager.getCachedData('spam_keywords');
        if (cachedKeywords) {
            console.log('Loading spam keywords from cache...');
            this.SPAM_KEYWORDS = cachedKeywords;
            return;
        }

        try {
            console.log('Fetching spam keywords from external source...');
            const response = UrlFetchApp.fetch(this.spamKeywordsSource, {
                method: 'GET',
                headers: { 'User-Agent': 'Mozilla/5.0 (compatible; GoogleAdsBot/1.0)' },
                muteHttpExceptions: true
            });

            if (response.getResponseCode() === 200) {
                this.SPAM_KEYWORDS = response.getContentText()
                    .split('\n')
                    .map(line => line.trim())
                    .filter(line => line && !line.startsWith('#') && !line.startsWith('//'))
                    .map(keyword => keyword.toLowerCase());
                
                // Cache the results
                this.cacheManager.setCachedData('spam_keywords', this.SPAM_KEYWORDS);
                console.log(`Loaded ${this.SPAM_KEYWORDS.length} spam keywords from external source`);
            } else {
                throw new Error(`HTTP ${response.getResponseCode()}`);
            }
        } catch (error) {
            console.log(`Failed to fetch spam keywords: ${error.message}, using fallback`);
            this.initializeFallbackSpamKeywords();
        }
    }

    initializeFallbackSpamKeywords() {
        // Minimal fallback list in case external source fails
        this.SPAM_KEYWORDS = [
            'free', 'crack', 'keygen', 'serial', 'torrent', 'pirate', 'warez', 'nulled', 'leaked',
            'game', 'gaming', 'entertainment', 'movie', 'music', 'streaming', 'download', 'mp3', 'mp4',
            'personal loan', 'credit card', 'mortgage', 'dating', 'singles', 'chat', 'facebook',
            'virus removal', 'pc cleaner', 'driver update', 'registry cleaner', 'antivirus free',
            'shocking', 'unbelievable', 'secret', 'trick', 'hack', 'amazing', 'incredible', 'viral',
            'adult', 'xxx', 'porn', 'sex', 'casino', 'poker', 'lottery', 'gambling', 'betting',
            'win money', 'earn cash', 'make money fast', 'get rich', 'investment opportunity'
        ];
        console.log(`Using fallback spam keywords: ${this.SPAM_KEYWORDS.length} terms`);
    }

    initializeB2BIndustrialTerms() {
        this.ENTERPRISE_RELEVANT_KEYWORDS = [
            'cnc machining', 'additive manufacturing', '3d printing', 'injection molding',
            'lean manufacturing', 'six sigma', 'kaizen', 'mes', 'scada', 'hmi', 'dcs',
            'iiot', 'industry 4.0', 'smart manufacturing', 'plm', 'cad', 'cam', 'cae',
            'fea', 'cfd', 'pdm', 'ecm', 'qms', 'iso 9001', 'spc', 'fmea',
            'erp', 'mrp', 'scm', 'crm', 'bi', 'etl', 'api integration', 'soa',
            'plc', 'servo drive', 'vfd', 'industrial ethernet', 'fieldbus', 'sis',
            'predictive maintenance', 'condition monitoring', 'machine learning',
            'artificial intelligence', 'digital twin', 'simulation', 'process optimization'
        ];
    }

    initializeWhitelistedDomains() {
        this.WHITELISTED_DOMAINS = [
            // Major industrial/tech companies
            'siemens.com', 'ge.com', 'honeywell.com', 'schneider-electric.com', 'rockwellautomation.com',
            'emerson.com', 'abb.com', 'mitsubishi.com', 'omron.com', 'fanuc.com',
            'solidworks.com', 'autodesk.com', 'ptc.com', 'dassaultsystemes.com', 'ansys.com',
            'sap.com', 'oracle.com', 'microsoft.com', 'salesforce.com', 'ibm.com',
            
            // Engineering publications
            'engineering.com', 'machinedesign.com', 'manufacturing.net', 'industryweek.com',
            'automationworld.com', 'controleng.com', 'qualitymag.com', 'assemblymag.com',
            
            // News and business
            'reuters.com', 'bloomberg.com', 'wsj.com', 'ft.com', 'economist.com',
            'forbes.com', 'harvard.edu', 'mit.edu', 'stanford.edu', 'ieee.org',
            
            // Government and standards
            'nist.gov', 'nasa.gov', 'energy.gov', 'iso.org', 'iec.ch', 'ansi.org'
        ];
    }

    initializeProfessionalDomains() {
        this.PROFESSIONAL_DOMAINS = [
            'siemens', 'ge', 'honeywell', 'schneider-electric', 'rockwellautomation',
            'emerson', 'abb', 'solidworks', 'autodesk', 'ptc', 'sap', 'oracle',
            'microsoft', 'salesforce', 'ibm', 'cisco', 'vmware'
        ];
    }

    async initializeSuspiciousTLDs() {
        // Try to load from cache first
        const cachedTLDs = this.cacheManager.getCachedData('suspicious_tlds');
        if (cachedTLDs) {
            console.log('Loading suspicious TLDs from cache...');
            this.SUSPICIOUS_TLDS = cachedTLDs;
            return;
        }

        try {
            const response = UrlFetchApp.fetch('https://raw.githubusercontent.com/cbuijs/accomplist/main/abuse-tlds/plain.black.domain.level-1.list.routedns', {
                method: 'GET',
                muteHttpExceptions: true
            });

            if (response.getResponseCode() === 200) {
                this.SUSPICIOUS_TLDS = response.getContentText()
                    .split('\n')
                    .map(line => line.trim())
                    .filter(line => line && !line.startsWith('#'))
                    .map(tld => tld.startsWith('.') ? tld : '.' + tld);
                
                // Cache the results
                this.cacheManager.setCachedData('suspicious_tlds', this.SUSPICIOUS_TLDS);
                console.log(`Loaded ${this.SUSPICIOUS_TLDS.length} suspicious TLDs from external source`);
            } else {
                throw new Error(`HTTP ${response.getResponseCode()}`);
            }
        } catch (error) {
            console.log(`Failed to fetch suspicious TLDs: ${error.message}, using fallback`);
            this.SUSPICIOUS_TLDS = [
                '.tk', '.ml', '.ga', '.cf', '.top', '.click', '.download', '.stream',
                '.racing', '.cricket', '.science', '.work', '.party', '.gq', '.link',
                '.date', '.loan', '.win', '.bid', '.trade', '.webcam', '.men'
            ];
        }
    }

    getSpamKeywords() {
        return this.SPAM_KEYWORDS || [];
    }
}

class TFIDFMetaAnalyzer {
    constructor() {
        this.stopWords = new Set([
            'a', 'an', 'and', 'are', 'as', 'at', 'be', 'by', 'for', 'from', 'has', 'he',
            'in', 'is', 'it', 'its', 'of', 'on', 'that', 'the', 'to', 'was', 'will',
            'with', 'we', 'you', 'your', 'our', 'this', 'these', 'they', 'them', 'their'
        ]);
        
        // Dynamic spam patterns that will be built from external keywords
        this.spamPatterns = [];
        this.initializeBasePatterns();
    }

    initializeBasePatterns() {
        // Base patterns for common obfuscation techniques
        this.spamPatterns = [
            // Critical patterns
            /\b(free|fr33|f r e e|freee)\b/gi,
            /\b(win|w1n|winn|winner|winning)\s*(money|cash|big|prizes?)/gi,
            /\b(casino|poker|lottery|gambling|bet|betting)\b/gi,
            /\b(adult|xxx|porn|sex|dating|singles)\b/gi,
            /\b(earn|make)\s*(money|cash|\$)\s*(fast|quick|easy|now)/gi,
            /\b(miracle|amazing|incredible|shocking|unbelievable)\b/gi,
            /\b(limited\s*time|act\s*now|hurry|urgent|expires?)\b/gi,
            /\b(guarantee|guaranteed|risk\s*free|no\s*risk)\b/gi,
            
            // Obfuscation patterns
            /\b(fr[3e]{2,}|f[r3]{2,}e|fre{3,})\b/gi,
            /\b(w[1i]{2,}n|wi{2,}n|w1nn?)\b/gi,
            /\b(m[0o]{2,}ney|mon[3e]{2,}y|m0n3y)\b/gi,
            /\b(c[4a]{2,}sh|ca[5s]{2,}h|c4sh)\b/gi
        ];
    }

    buildDynamicSpamPatterns() {
        // Build additional patterns from external spam keywords
        const spamKeywords = globalThis.keywordConfig?.getSpamKeywords() || [];
        
        spamKeywords.forEach(keyword => {
            if (keyword.length > 2) {
                // Create regex pattern for exact matches with word boundaries
                const escapedKeyword = keyword.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
                const pattern = new RegExp(`\\b${escapedKeyword}\\b`, 'gi');
                this.spamPatterns.push(pattern);
            }
        });
        
        console.log(`Built ${this.spamPatterns.length} spam detection patterns`);
    }

    extractAndAnalyzeMetaContent(html) {
        // Ensure dynamic patterns are built
        if (globalThis.keywordConfig?.getSpamKeywords()?.length > 0 && this.spamPatterns.length < 50) {
            this.buildDynamicSpamPatterns();
        }

        const metaContent = this.extractMetaContent(html);
        const allText = this.combineMetaText(metaContent);
        const tfidfKeywords = this.performTFIDFAnalysis(allText);
        const spamAnalysis = this.performSpamAnalysis(allText);
        
        return {
            metaContent,
            tfidfKeywords,
            spamAnalysis,
            combinedKeywords: this.generateCombinedKeywords(tfidfKeywords, spamAnalysis),
            spamScore: spamAnalysis.totalSpamScore,
            professionalScore: this.calculateProfessionalScore(allText),
            detectedSpamKeywords: spamAnalysis.detectedSpamKeywords || []
        };
    }

    extractMetaContent(html) {
        const metaContent = { title: '', description: '', keywords: '' };
        
        const titleMatch = html.match(/<title[^>]*>([^<]*)<\/title>/i);
        if (titleMatch) metaContent.title = titleMatch[1].trim();

        const metaRegex = /<meta[^>]*(?:name|property)=["']([^"']*)["'][^>]*content=["']([^"']*)["'][^>]*>/gi;
        let match;
        while ((match = metaRegex.exec(html)) !== null) {
            const name = match[1].toLowerCase();
            const content = match[2].trim();
            if (name === 'description') metaContent.description = content;
            if (name === 'keywords') metaContent.keywords = content;
        }
        
        return metaContent;
    }

    combineMetaText(metaContent) {
        return [metaContent.title, metaContent.description, metaContent.keywords]
            .filter(text => text && text.length > 0)
            .join(' ');
    }

    performTFIDFAnalysis(text) {
        const words = this.tokenizeText(text);
        const termFreq = {};
        words.forEach(word => termFreq[word] = (termFreq[word] || 0) + 1);

        return Object.entries(termFreq)
            .sort((a, b) => b[1] - a[1])
            .slice(0, 5)
            .map(([term, frequency]) => ({ term, frequency }));
    }

    tokenizeText(text) {
        return text.toLowerCase()
            .replace(/[^a-z0-9\s]/g, ' ')
            .split(/\s+/)
            .filter(word => word.length > 2 && !this.stopWords.has(word) && !/^\d+$/.test(word));
    }

    performSpamAnalysis(text) {
        const spamResults = { 
            criticalSpam: [], 
            totalSpamScore: 0, 
            spamFlags: [],
            detectedSpamKeywords: []
        };
        
        this.spamPatterns.forEach((pattern, index) => {
            const matches = text.match(pattern) || [];
            if (matches.length > 0) {
                const score = matches.length * (index < 8 ? -2.0 : -1.6); // Critical vs obfuscation
                spamResults.criticalSpam.push({ pattern: pattern.toString(), matches: matches.length, score });
                spamResults.totalSpamScore += score;
                spamResults.spamFlags.push('SPAM_DETECTED');
                
                // Add detected spam keywords
                matches.forEach(match => {
                    if (!spamResults.detectedSpamKeywords.includes(match.toLowerCase())) {
                        spamResults.detectedSpamKeywords.push(match.toLowerCase());
                    }
                });
            }
        });
        
        return spamResults;
    }

    calculateProfessionalScore(text) {
        let score = 0;
        const lowerText = text.toLowerCase();
        globalThis.keywordConfig?.ENTERPRISE_RELEVANT_KEYWORDS?.forEach(term => {
            if (lowerText.includes(term)) score += 0.5;
        });
        return Math.min(score, 3.0);
    }

    generateCombinedKeywords(tfidfKeywords, spamAnalysis) {
        const keywords = [];
        
        if (spamAnalysis.criticalSpam.length > 0) {
            const totalMatches = spamAnalysis.criticalSpam.reduce((sum, item) => sum + item.matches, 0);
            const totalScore = spamAnalysis.criticalSpam.reduce((sum, item) => sum + item.score, 0);
            const spamKeywords = spamAnalysis.detectedSpamKeywords.slice(0, 3).join(', ');
            keywords.push(`SPAM: ${totalMatches} matches (${totalScore.toFixed(2)}) - Keywords: ${spamKeywords}`);
        }
        
        if (spamAnalysis.criticalSpam.length === 0 && tfidfKeywords.length > 0) {
            const topKeywords = tfidfKeywords
                .map(item => `${item.term}(${item.frequency})`)
                .join(', ');
            keywords.push(`KEYWORDS: ${topKeywords}`);
        }
        
        return keywords.length > 0 ? keywords.join(' | ') : 'no significant keywords found';
    }
}

class EnterpriseURLQualityAssessor {
    constructor() {
        this.SCORING_WEIGHTS = {
            DOMAIN_AUTHORITY: 0.15,
            CONTENT_RELEVANCE: 0.25,
            TECHNICAL_QUALITY: 0.20,
            SPAM_INDICATORS: 0.40
        };
        this.CONTENT_FETCH_TIMEOUT = URL_TIMEOUT_SECONDS * 1000;
        this.MAX_CONTENT_SIZE = 700000;
        this.fetchTimes = [];
        this.tfidfAnalyzer = new TFIDFMetaAnalyzer();
        
        // Consolidated keywords for efficiency
        this.INDUSTRIAL_KEYWORDS = [
            'manufacturing', 'factory', 'industrial', 'machinery', 'equipment',
            'automation', 'assembly', 'production', 'engineering', 'cad', 'plm'
        ];
        this.B2B_INDICATORS = ['enterprise', 'industrial', 'solution', 'software', 'platform', 'system'];
        this.HEADING_WEIGHTS = { 'h1': 3.0, 'h2': 2.0, 'h3': 1.5, 'h4': 1.0, 'h5': 0.8, 'h6': 0.6 };
    }

    async performAdvancedDNSLookup(domain) {
        const dnsInfo = {
            success: false, ipAddresses: [], mxRecords: [], txtRecords: [],
            hostingProvider: null, isCloudflare: false, isAWS: false, isEnterprise: false,
            lookupTime: 0, error: null, isBlacklistedIP: false, blacklistedIPs: []
        };

        const startTime = Date.now();

        try {
            const response = UrlFetchApp.fetch(`https://1.1.1.1/dns-query?name=${domain}&type=A`, {
                method: 'GET',
                headers: { 'Accept': 'application/dns-json' },
                muteHttpExceptions: true
            });

            dnsInfo.lookupTime = Date.now() - startTime;

            if (response.getResponseCode() === 200) {
                const dnsData = JSON.parse(response.getContentText());
                
                if (dnsData.Status === 0 && dnsData.Answer) {
                    dnsInfo.success = true;
                    dnsInfo.ipAddresses = dnsData.Answer.filter(r => r.type === 1).map(r => r.data);

                    // Check for blacklisted IPs
                    dnsInfo.ipAddresses.forEach(ip => {
                        if (globalThis.blocklistManager?.isIPBlocked(ip)) {
                            dnsInfo.isBlacklistedIP = true;
                            dnsInfo.blacklistedIPs.push(ip);
                        }
                    });

                    // Analyze hosting provider
                    dnsInfo.ipAddresses.forEach(ip => {
                        const hostingInfo = this.analyzeIPAddress(ip);
                        if (hostingInfo.provider) {
                            Object.assign(dnsInfo, hostingInfo);
                        }
                    });

                    // Additional DNS queries
                    await this.performAdditionalDNSQueries(domain, dnsInfo);
                } else {
                    dnsInfo.error = `DNS query failed: ${dnsData.Status}`;
                }
            } else {
                dnsInfo.error = `HTTP ${response.getResponseCode()}`;
            }
        } catch (error) {
            dnsInfo.lookupTime = Date.now() - startTime;
            dnsInfo.error = error.message;
        }

        return dnsInfo;
    }

    analyzeIPAddress(ip) {
        const cloudflareRanges = ['104.16.', '104.17.', '104.18.', '104.19.', '104.20.', '104.21.',
                                 '104.22.', '104.23.', '104.24.', '104.25.', '104.26.', '104.27.',
                                 '104.28.', '104.29.', '104.30.', '104.31.', '172.64.', '172.65.',
                                 '172.66.', '172.67.', '172.68.', '172.69.', '172.70.', '172.71.'];
        
        const awsRanges = ['52.', '54.', '3.', '13.', '18.', '34.', '35.'];
        const enterpriseRanges = ['20.', '40.', '52.', '104.', '35.', '34.'];

        if (cloudflareRanges.some(range => ip.startsWith(range))) {
            return { provider: 'cloudflare', isCloudflare: true, isAWS: false, isEnterprise: true };
        }
        
        if (awsRanges.some(range => ip.startsWith(range))) {
            return { provider: 'aws', isCloudflare: false, isAWS: true, isEnterprise: true };
        }
        
        return { 
            provider: null, 
            isCloudflare: false, 
            isAWS: false, 
            isEnterprise: enterpriseRanges.some(range => ip.startsWith(range))
        };
    }

    async performAdditionalDNSQueries(domain, dnsInfo) {
        try {
            const [mxResponse, txtResponse] = await Promise.all([
                this.queryDNSRecord(domain, 'MX'),
                this.queryDNSRecord(domain, 'TXT')
            ]);

            if (mxResponse.success) dnsInfo.mxRecords = mxResponse.records;
            if (txtResponse.success) {
                dnsInfo.txtRecords = txtResponse.records;
                // Check for AWS in SPF records
                if (txtResponse.records.some(r => r.data.includes('v=spf1') && r.data.includes('amazonaws.com'))) {
                    dnsInfo.isAWS = true;
                    dnsInfo.hostingProvider = 'aws';
                }
            }
        } catch (error) {
            console.log(`Additional DNS queries failed: ${error.message}`);
        }
    }

    async queryDNSRecord(domain, recordType) {
        try {
            const response = UrlFetchApp.fetch(`https://1.1.1.1/dns-query?name=${domain}&type=${recordType}`, {
                method: 'GET',
                headers: { 'Accept': 'application/dns-json' },
                muteHttpExceptions: true
            });

            if (response.getResponseCode() === 200) {
                const dnsData = JSON.parse(response.getContentText());
                if (dnsData.Status === 0 && dnsData.Answer) {
                    return {
                        success: true,
                        records: dnsData.Answer.map(record => ({
                            type: record.type, data: record.data, ttl: record.TTL
                        }))
                    };
                }
            }
            return { success: false, records: [] };
        } catch (error) {
            return { success: false, error: error.message, records: [] };
        }
    }

    validateAndNormalizeURL(url) {
        if (!url || typeof url !== 'string') throw new Error('URL is empty or not a string');
        
        url = url.trim();
        if (!url) throw new Error('URL is empty');
        if (!url.match(/^https?:\/\//i)) url = 'https://' + url;
        if (!url.match(/^https?:\/\/[^\s]+$/i)) throw new Error('URL format appears invalid');
        
        return url;
    }

    extractDomainSafely(url) {
        try {
            return new URL(this.validateAndNormalizeURL(url)).hostname.toLowerCase();
        } catch (error) {
            const match = url.match(/(?:https?:\/\/)?(?:www\.)?([^\/?#]+)/i);
            return match ? match[1].toLowerCase() : 'unknown-domain';
        }
    }

    assessURLSpamIndicators(fullUrl, domain) {
        // Quick whitelist check
        if (globalThis.keywordConfig?.WHITELISTED_DOMAINS?.some(d => domain.includes(d))) return { score: 1.0, detectedSpamKeywords: [] };

        let score = 1.0;
        let spamMatches = 0;
        const detectedSpamKeywords = [];

        // Critical patterns with heavy penalties
        const criticalPatterns = [
            /\b(free|casino|win|adult|xxx|porn|dating|lottery|gambling)\b/gi,
            /\d{4,}/g,
            /[\-_]{3,}/g,
            /\b(download|crack|keygen|serial|torrent|stream)\b/gi
        ];

        criticalPatterns.forEach(pattern => {
            const matches = fullUrl.match(pattern) || [];
            if (matches.length > 0) {
                spamMatches += matches.length;
                score -= matches.length * 0.4;
                matches.forEach(match => {
                    if (!detectedSpamKeywords.includes(match.toLowerCase())) {
                        detectedSpamKeywords.push(match.toLowerCase());
                    }
                });
            }
        });

        // Check against external spam keywords
        const spamKeywords = globalThis.keywordConfig?.getSpamKeywords() || [];
        spamKeywords.forEach(keyword => {
            if (fullUrl.includes(keyword.toLowerCase())) {
                spamMatches++;
                score -= 0.2;
                if (!detectedSpamKeywords.includes(keyword)) {
                    detectedSpamKeywords.push(keyword);
                }
            }
        });

        // Exponential penalties for multiple spam indicators
        if (spamMatches >= 3) score -= 0.4;
        if (spamMatches >= 5) score -= 0.6;
        if (/xn--/.test(domain)) score -= 0.2;

        return { 
            score: Math.max(0, Math.min(1, score)),
            detectedSpamKeywords: detectedSpamKeywords
        };
    }

    async fetchAndAnalyzeContentWithTimeout(url) {
        const startTime = Date.now();
        const contentAnalysis = {
            fetchSuccess: false, metaTags: {}, headings: [], images: [],
            industrialIndicators: 0, spamIndicators: 0, b2bIndicators: 0, rawHtml: '',
            detectedSpamKeywords: []
        };

        try {
            const response = UrlFetchApp.fetch(url, {
                method: 'GET',
                headers: { 'User-Agent': 'Mozilla/5.0 (compatible; GoogleAdsBot/1.0)' },
                muteHttpExceptions: true
            });

            const fetchDuration = Date.now() - startTime;
            this.fetchTimes.push({ url, duration: fetchDuration, timestamp: new Date() });

            if (response.getResponseCode() !== 200) {
                throw new Error(`HTTP ${response.getResponseCode()}`);
            }

            const html = response.getContentText().substring(0, this.MAX_CONTENT_SIZE);
            contentAnalysis.fetchSuccess = true;
            contentAnalysis.rawHtml = html;

            // Parse content efficiently
            this.parseContent(html, contentAnalysis);
            this.calculateContentScores(contentAnalysis);

        } catch (error) {
            throw error;
        }

        return contentAnalysis;
    }

    parseContent(html, contentAnalysis) {
        // Parse meta tags
        const titleMatch = html.match(/<title[^>]*>([^<]*)<\/title>/i);
        if (titleMatch) contentAnalysis.metaTags.title = titleMatch[1];

        const descMatch = html.match(/<meta[^>]*name=["']description["'][^>]*content=["']([^"']*)["'][^>]*>/i);
        if (descMatch) contentAnalysis.metaTags.description = descMatch[1];

        // Parse headings efficiently
        for (let level = 1; level <= 6; level++) {
            const headingRegex = new RegExp(`<h${level}[^>]*>([^<]*)</h${level}>`, 'gi');
            let match;
            while ((match = headingRegex.exec(html)) !== null) {
                contentAnalysis.headings.push({
                    level, text: match[1].toLowerCase().trim(), weight: this.HEADING_WEIGHTS[`h${level}`]
                });
            }
        }

        // Parse images
        const imgRegex = /<img[^>]*alt=["']([^"']*)["'][^>]*>/gi;
        let match;
        while ((match = imgRegex.exec(html)) !== null) {
            const altText = match[1].toLowerCase().trim();
            if (altText && altText.length > 2) {
                contentAnalysis.images.push({
                    altText,
                    isIndustrial: this.INDUSTRIAL_KEYWORDS.some(keyword => altText.includes(keyword))
                });
            }
        }
    }

    calculateContentScores(contentAnalysis) {
        let industrialScore = 0, spamScore = 0, b2bScore = 0;
        const allMetaText = Object.values(contentAnalysis.metaTags).join(' ').toLowerCase();
        
        // Score industrial relevance
        globalThis.keywordConfig?.ENTERPRISE_RELEVANT_KEYWORDS?.forEach(keyword => {
            if (allMetaText.includes(keyword)) industrialScore += 0.1;
        });

        // Score B2B indicators
        this.B2B_INDICATORS.forEach(indicator => {
            if (allMetaText.includes(indicator)) b2bScore += 0.1;
        });

        // Score spam content using external keywords
        const spamKeywords = globalThis.keywordConfig?.getSpamKeywords() || [];
        spamKeywords.forEach(keyword => {
            if (allMetaText.includes(keyword)) {
                spamScore += 0.15;
                if (!contentAnalysis.detectedSpamKeywords.includes(keyword)) {
                    contentAnalysis.detectedSpamKeywords.push(keyword);
                }
            }
        });

        // Score headings
        contentAnalysis.headings.forEach(heading => {
            globalThis.keywordConfig?.ENTERPRISE_RELEVANT_KEYWORDS?.forEach(keyword => {
                if (heading.text.includes(keyword)) {
                    industrialScore += 0.05 * heading.weight;
                }
            });
        });

        // Score industrial images
        if (contentAnalysis.images.length > 0) {
            const industrialImages = contentAnalysis.images.filter(img => img.isIndustrial).length;
            industrialScore += (industrialImages / contentAnalysis.images.length) * 0.2;
        }

        contentAnalysis.industrialIndicators = Math.min(1.0, industrialScore);
        contentAnalysis.spamIndicators = Math.min(1.0, spamScore);
        contentAnalysis.b2bIndicators = Math.min(1.0, b2bScore);
    }

    assessDomainQuality(domain) {
        let score = 0.5;

        // Whitelist boost
        if (globalThis.keywordConfig?.WHITELISTED_DOMAINS?.some(d => domain.includes(d))) score += 0.5;
        if (globalThis.keywordConfig?.PROFESSIONAL_DOMAINS?.some(d => domain.includes(d))) score += 0.4;

        // TLD analysis
        const tld = domain.substring(domain.lastIndexOf('.'));
        if (globalThis.keywordConfig?.SUSPICIOUS_TLDS?.includes(tld)) {
            score -= 0.3;
        } else if (['.com', '.org', '.edu', '.gov', '.net'].includes(tld)) {
            score += 0.2;
        }

        // Domain structure penalties
        const sld = domain.split('.')[domain.split('.').length - 2] || '';
        if (sld.length < 3 || sld.length > 25) score -= 0.2;
        if (sld.includes('-')) score -= 0.1;
        if (/\d{3,}/.test(sld)) score -= 0.2;

        return Math.max(0, Math.min(1, score));
    }

    assessContentRelevance(fullUrl, domain, path) {
        let score = 0;

        // Whitelist boost
        if (globalThis.keywordConfig?.WHITELISTED_DOMAINS?.some(d => domain.includes(d))) score += 0.3;

        // Keyword relevance
        let relevantMatches = 0;
        globalThis.keywordConfig?.ENTERPRISE_RELEVANT_KEYWORDS?.forEach(keyword => {
            if (fullUrl.includes(keyword.toLowerCase())) {
                relevantMatches++;
                score += 0.1;
            }
        });

        if (relevantMatches >= 3) score += 0.2;

        // Path analysis
        const industryPaths = ['/manufacturing', '/engineering', '/plm', '/cad', '/software', '/solutions', '/products', '/enterprise', '/industrial'];
        if (industryPaths.some(p => path.includes(p))) score += 0.2;

        // B2B indicators
        if (['enterprise', 'business', 'professional', 'industrial', 'commercial'].some(indicator => fullUrl.includes(indicator))) {
            score += 0.1;
        }

        return Math.max(0, Math.min(1, score));
    }

    assessTechnicalQuality(domain, path, params, dnsInfo) {
        let score = 0.7;

        // Whitelist boost
        if (globalThis.keywordConfig?.WHITELISTED_DOMAINS?.some(d => domain.includes(d))) score += 0.2;

        // URL structure penalties
        if (path.length > 100) score -= 0.1;
        if ((params.match(/&/g) || []).length > 10) score -= 0.2;
        if (['.exe', '.zip', '.rar', '.dmg', '.apk'].some(ext => path.includes(ext))) score -= 0.4;
        if (['bit.ly', 'tinyurl', 't.co', 'goo.gl', 'ow.ly'].some(short => domain.includes(short))) score -= 0.3;

        // DNS-based scoring
        if (dnsInfo?.success) {
            if (dnsInfo.isBlacklistedIP) score -= 0.5; // Heavy penalty for blacklisted IPs
            if (dnsInfo.ipAddresses.length > 1) score += 0.1;
            if (dnsInfo.isEnterprise) score += 0.15;
            if (dnsInfo.lookupTime < 500) score += 0.1;
            else if (dnsInfo.lookupTime > 3000) score -= 0.15;
            if (dnsInfo.isCloudflare) score += 0.05;
            if (dnsInfo.isAWS) score += 0.12;
            if (dnsInfo.mxRecords?.length > 0) score += 0.08;
        } else if (dnsInfo && !dnsInfo.success) {
            score -= 0.2;
        }

        return Math.max(0, Math.min(1, score));
    }

    integrateContentAnalysis(assessment) {
        if (!assessment.contentAnalysis?.fetchSuccess) return;

        const content = assessment.contentAnalysis;

        // Boost scores for good content
        if (content.industrialIndicators > 0.5 || content.b2bIndicators > 0.5) {
            assessment.scores.domainQuality = Math.min(1.0, assessment.scores.domainQuality + 0.2);
        }
        if (content.industrialIndicators > 0.3) {
            assessment.scores.contentRelevance = Math.min(1.0, assessment.scores.contentRelevance + 0.3);
        }
        if (content.metaTags.description && content.headings.length >= 3) {
            assessment.scores.technicalQuality = Math.min(1.0, assessment.scores.technicalQuality + 0.1);
        }

        // Heavy spam penalty
        if (content.spamIndicators > 0.3) {
            assessment.scores.spamIndicators = Math.max(0, assessment.scores.spamIndicators - 0.4);
        }
    }

    calculateOverallScore(scores) {
        return (
            scores.domainQuality * this.SCORING_WEIGHTS.DOMAIN_AUTHORITY +
            scores.contentRelevance * this.SCORING_WEIGHTS.CONTENT_RELEVANCE +
            scores.technicalQuality * this.SCORING_WEIGHTS.TECHNICAL_QUALITY +
            scores.spamIndicators * this.SCORING_WEIGHTS.SPAM_INDICATORS
        );
    }

    generateRecommendation(score) {
        if (score >= QUALITY_THRESHOLDS.HIGH_QUALITY) return QUALITY_LABELS.HIGH_QUALITY;
        if (score >= QUALITY_THRESHOLDS.MEDIUM_QUALITY) return QUALITY_LABELS.MEDIUM_QUALITY;
        return QUALITY_LABELS.LOW_QUALITY;
    }

    collectFlags(assessment, domain, path, fullUrl) {
        const { scores, tfidfAnalysis, dnsInfo } = assessment;
        
        // Critical issues
        if (dnsInfo?.isBlacklistedIP) {
            assessment.flags.push('BLACKLISTED_IP');
            assessment.reasons.push(`blacklisted IP detected: ${dnsInfo.blacklistedIPs.join(', ')}`);
        }
        
        if (scores.spamIndicators < 0.2) {
            assessment.flags.push('CRITICAL_SPAM_DETECTED');
            assessment.reasons.push('critical spam indicators in URL detected');
        }
        
        if (tfidfAnalysis?.spamAnalysis?.criticalSpam?.length > 0) {
            assessment.flags.push('META_SPAM');
            const spamKeywords = tfidfAnalysis.detectedSpamKeywords?.slice(0, 3).join(', ') || 'various';
            assessment.reasons.push(`spam patterns in meta content: ${spamKeywords}`);
        }
        
        // Positive indicators
        if (tfidfAnalysis?.professionalScore > 1.0) {
            assessment.flags.push('PROFESSIONAL_CONTENT');
            assessment.reasons.push(`excellent professional content (score: ${tfidfAnalysis.professionalScore.toFixed(1)})`);
        }

        // Technical issues
        if (!assessment.contentAnalysis?.fetchSuccess) {
            assessment.flags.push('NO_CONTENT_ANALYSIS');
            assessment.reasons.push('content analysis unavailable - technical issues');
        }

        // Domain quality
        if (globalThis.keywordConfig?.WHITELISTED_DOMAINS?.some(d => domain.includes(d))) {
            assessment.flags.push('WHITELISTED_DOMAIN');
            assessment.reasons.push('domain is whitelisted - trusted source');
        }

        const tld = domain.substring(domain.lastIndexOf('.'));
        if (globalThis.keywordConfig?.SUSPICIOUS_TLDS?.includes(tld)) {
            assessment.flags.push('SUSPICIOUS_TLD');
            assessment.reasons.push(`suspicious top-level domain: ${tld}`);
        }

        // DNS quality indicators
        if (dnsInfo?.isEnterprise) {
            assessment.flags.push('ENTERPRISE_HOSTING');
            assessment.reasons.push(`enterprise-grade hosting: ${dnsInfo.hostingProvider || 'detected'}`);
        }
    }

    async assessURL(url, impressions = 0, enableContentFetch = true) {
        if (!url?.trim()) {
            return {
                url: url || 'N/A', error: 'Empty or invalid URL provided',
                recommendation: QUALITY_LABELS.LOW_QUALITY, overallScore: 0,
                reasons: ['empty or invalid url'], metaKeywords: 'invalid url',
                flaggedTerms: ''
            };
        }

        try {
            const normalizedUrl = this.validateAndNormalizeURL(url);
            let domain, path, params, fullUrl;
            
            try {
                const urlObj = new URL(normalizedUrl);
                domain = urlObj.hostname.toLowerCase();
                path = urlObj.pathname.toLowerCase();
                params = urlObj.search.toLowerCase();
                fullUrl = normalizedUrl.toLowerCase();
            } catch (urlError) {
                domain = this.extractDomainSafely(url);
                path = params = '';
                fullUrl = normalizedUrl.toLowerCase();
            }

            const assessment = {
                url, domain, impressions, scores: {}, flags: [], overallScore: 0,
                recommendation: '', reasons: [], contentAnalysis: null, dnsInfo: null,
                metaKeywords: 'content analysis pending', tfidfAnalysis: null,
                urlSpamKeywords: [], flaggedTerms: ''
            };

            // DNS lookup
            try {
                assessment.dnsInfo = await this.performAdvancedDNSLookup(domain);
            } catch (error) {
                assessment.dnsInfo = { success: false, error: error.message, lookupTime: 0 };
            }

            // Core assessments
            assessment.scores.domainQuality = this.assessDomainQuality(domain);
            assessment.scores.contentRelevance = this.assessContentRelevance(fullUrl, domain, path);
            assessment.scores.technicalQuality = this.assessTechnicalQuality(domain, path, params, assessment.dnsInfo);
            
            const urlSpamResult = this.assessURLSpamIndicators(fullUrl, domain);
            assessment.scores.spamIndicators = urlSpamResult.score;
            assessment.urlSpamKeywords = urlSpamResult.detectedSpamKeywords;

            // Content analysis
            if (enableContentFetch) {
                try {
                    assessment.contentAnalysis = await this.fetchAndAnalyzeContentWithTimeout(normalizedUrl);
                    
                    if (assessment.contentAnalysis?.fetchSuccess) {
                        assessment.tfidfAnalysis = this.tfidfAnalyzer.extractAndAnalyzeMetaContent(assessment.contentAnalysis.rawHtml);
                        
                        // Apply TF-IDF results
                        const metaSpamPenalty = Math.abs(assessment.tfidfAnalysis.spamScore) * 0.5;
                        assessment.scores.spamIndicators = Math.max(0, assessment.scores.spamIndicators - metaSpamPenalty);
                        
                        const professionalBoost = Math.min(0.4, assessment.tfidfAnalysis.professionalScore * 0.2);
                        assessment.scores.contentRelevance = Math.min(1.0, assessment.scores.contentRelevance + professionalBoost);
                        
                        // Combine spam keywords from URL and meta content
                        const allSpamKeywords = [
                            ...assessment.urlSpamKeywords,
                            ...(assessment.tfidfAnalysis.detectedSpamKeywords || []),
                            ...(assessment.contentAnalysis.detectedSpamKeywords || [])
                        ];
                        const uniqueSpamKeywords = [...new Set(allSpamKeywords)];
                        
                        if (uniqueSpamKeywords.length > 0) {
                            assessment.metaKeywords = `SPAM DETECTED: ${uniqueSpamKeywords.slice(0, 5).join(', ')} | ${assessment.tfidfAnalysis.combinedKeywords}`;
                        } else {
                            assessment.metaKeywords = assessment.tfidfAnalysis.combinedKeywords;
                        }

                        // Generate flagged terms
                        assessment.flaggedTerms = this.generateFlaggedTerms(
                            assessment.urlSpamKeywords,
                            assessment.tfidfAnalysis.detectedSpamKeywords || [],
                            assessment.contentAnalysis.detectedSpamKeywords || []
                        );
                    }
                    
                    this.integrateContentAnalysis(assessment);
                } catch (error) {
                    assessment.flags.push('CONTENT_FETCH_FAILED');
                    assessment.metaKeywords = error.message.includes('timeout') ? 
                        `content fetch timeout (>${URL_TIMEOUT_SECONDS}s)` : 'content fetch failed';
                }
            } else {
                assessment.metaKeywords = 'content fetch disabled';
                // Generate flagged terms from URL only
                assessment.flaggedTerms = this.generateFlaggedTerms(assessment.urlSpamKeywords, [], []);
            }

            assessment.overallScore = this.calculateOverallScore(assessment.scores);
            assessment.recommendation = this.generateRecommendation(assessment.overallScore);
            this.collectFlags(assessment, domain, path, fullUrl);

            return assessment;

        } catch (error) {
            return {
                url, error: `Assessment error: ${error.message}`,
                recommendation: QUALITY_LABELS.LOW_QUALITY, overallScore: 0,
                reasons: ['url assessment failed'], metaKeywords: 'assessment failed',
                flaggedTerms: ''
            };
        }
    }

    generateFlaggedTerms(urlSpamKeywords, metaSpamKeywords, contentSpamKeywords) {
        const flaggedParts = [];
        
        if (urlSpamKeywords.length > 0) {
            flaggedParts.push(`URL: ${urlSpamKeywords.slice(0, 5).join(', ')}`);
        }
        
        const allMetaKeywords = [...new Set([...metaSpamKeywords, ...contentSpamKeywords])];
        if (allMetaKeywords.length > 0) {
            flaggedParts.push(`Meta Content: ${allMetaKeywords.slice(0, 5).join(', ')}`);
        }
        
        return flaggedParts.join('\n');
    }

    getSlowUrls() {
        if (this.fetchTimes.length === 0) return [];
        const sorted = [...this.fetchTimes].sort((a, b) => b.duration - a.duration);
        return sorted.slice(0, Math.floor(sorted.length * 0.2));
    }
}

async function checkPlacementWithQualityAnalysis(performanceMaxPlacement) {
    // Initialize managers
    if (typeof globalThis.blocklistManager === 'undefined') {
        globalThis.blocklistManager = new BlocklistManager();
        if (globalThis.blocklistManager.shouldRefreshBlocklist()) {
            await globalThis.blocklistManager.fetchBlocklist();
        }
    }
    
    if (typeof globalThis.urlAssessor === 'undefined') {
        globalThis.urlAssessor = new EnterpriseURLQualityAssessor();
    }
    
    // Check blocklist first
    if (performanceMaxPlacement.targetUrl) {
        try {
            const domain = globalThis.urlAssessor.extractDomainSafely(performanceMaxPlacement.targetUrl);
            if (globalThis.blocklistManager.isDomainBlocked(domain)) {
                return {
                    exclude: true,
                    reason: 'domain found in external blocklist - automatic exclusion for security',
                    score: 0,
                    suggestion: QUALITY_LABELS.LOW_QUALITY,
                    metaKeywords: 'BLOCKLIST_MATCH',
                    blocklistMatch: true,
                    flaggedTerms: 'URL: blocklist match'
                };
            }
        } catch (error) {
            console.log(`Error checking blocklist: ${error.message}`);
        }
    }
    
    // Handle different placement types
    if (performanceMaxPlacement.placementType == 'MOBILE_APPLICATION') {
        return {
            exclude: true,
            reason: 'mobile app placement - exclude',
            score: 0.1,
            suggestion: QUALITY_LABELS.LOW_QUALITY,
            metaKeywords: 'mobile app',
            flaggedTerms: ''
        };
    }

    if (performanceMaxPlacement.placementType == 'YOUTUBE_VIDEO') {
        return {
            exclude: true,
            reason: 'youtube video placement - exclude',
            score: 0.2,
            suggestion: QUALITY_LABELS.LOW_QUALITY,
            metaKeywords: 'youtube video',
            flaggedTerms: ''
        };
    }

    if (performanceMaxPlacement.placementType == 'WEBSITE') {
        try {
            const assessment = await globalThis.urlAssessor.assessURL(
                performanceMaxPlacement.targetUrl,
                performanceMaxPlacement.impressions,
                true
            );

            let reason = assessment.reasons ? assessment.reasons.join(', ') : '';
            
            if (assessment.tfidfAnalysis) {
                if (assessment.tfidfAnalysis.spamAnalysis.criticalSpam.length > 0) {
                    reason += (reason ? ', ' : '') + 'critical meta spam content detected';
                }
                if (assessment.tfidfAnalysis.professionalScore > 1.0) {
                    reason += (reason ? ', ' : '') + 'likely professional/technical content detected';
                }
            }

            if (assessment.dnsInfo?.isBlacklistedIP) {
                reason += (reason ? ', ' : '') + 'hosting on blacklisted IP addresses';
            }

            return {
                exclude: assessment.recommendation === QUALITY_LABELS.LOW_QUALITY,
                reason: reason || 'standard quality assessment completed',
                score: assessment.overallScore,
                suggestion: assessment.recommendation,
                metaKeywords: assessment.metaKeywords,
                blocklistMatch: false,
                flaggedTerms: assessment.flaggedTerms || ''
            };

        } catch (error) {
            return {
                exclude: true,
                reason: 'analysis failed - unable to assess quality due to technical issues',
                score: 0,
                suggestion: QUALITY_LABELS.LOW_QUALITY,
                metaKeywords: 'analysis failed',
                flaggedTerms: ''
            };
        }
    }

    return {
        exclude: false,
        reason: 'no quality issues detected - placement type likely acceptable',
        score: 0.8,
        suggestion: QUALITY_LABELS.HIGH_QUALITY,
        metaKeywords: 'other placement type',
        flaggedTerms: ''
    };
}

function getDateRange(lookbackDays) {
    const endDate = new Date();
    const startDate = new Date();
    startDate.setDate(endDate.getDate() - lookbackDays);
    
    return {
        startDate: Utilities.formatDate(startDate, AdsApp.currentAccount().getTimeZone(), 'yyyy-MM-dd'),
        endDate: Utilities.formatDate(endDate, AdsApp.currentAccount().getTimeZone(), 'yyyy-MM-dd')
    };
}

async function main() {
    const startTime = new Date();
    console.log('Starting Enhanced Performance Max Placement Analysis...');
    
    // Log configuration
    console.log(`\n=== CONFIGURATION ===`);
    console.log(`Add to Account Exclusions: ${ADD_TO_ACCOUNT_EXCLUSIONS}`);
    console.log(`Auto-Exclusion Threshold: ${AUTO_EXCLUSION_THRESHOLD}`);
    console.log(`Dry Run Mode: ${DRY_RUN_MODE}`);
    
    // Initialize configurations
    if (typeof globalThis.keywordConfig === 'undefined') {
        globalThis.keywordConfig = new KeywordConfiguration();
        await globalThis.keywordConfig.initializeSuspiciousTLDs(); // Async TLD fetch with caching
        await globalThis.keywordConfig.initializeSpamKeywords(); // Async spam keywords fetch with caching
    }
    
    if (typeof globalThis.blocklistManager === 'undefined') {
        globalThis.blocklistManager = new BlocklistManager();
        await globalThis.blocklistManager.fetchBlocklist();
    }

    // Initialize exclusion manager
    const exclusionManager = new AccountExclusionManager();
    
    const accountName = AdsApp.currentAccount().getName();
    const allResults = [];
    const analysisResults = [];
    const placementsForExclusion = [];
    const uniqueUrls = new Set();
    let lowQualityCount = 0;
    let blocklistMatchCount = 0;
    
    const dateRange = getDateRange(LOOKBACK_WINDOW);
    
    const query = `
        SELECT campaign.id, performance_max_placement_view.display_name, 
               performance_max_placement_view.placement, performance_max_placement_view.placement_type, 
               performance_max_placement_view.resource_name, performance_max_placement_view.target_url, 
               metrics.impressions
        FROM performance_max_placement_view
        WHERE metrics.impressions > ${MIN_IMPRESSIONS}
          AND segments.date BETWEEN '${dateRange.startDate}' AND '${dateRange.endDate}'
        ORDER BY metrics.impressions DESC
    `;
    
    console.log('Executing GAQL query...');
    
    try {
        const result = AdsApp.search(query);
        
        while (result.hasNext()) {
            const row = result.next();
            
            const placement = {
                campaignId: row.campaign.id,
                displayName: row.performanceMaxPlacementView.displayName,
                placement: row.performanceMaxPlacementView.placement,
                placementType: row.performanceMaxPlacementView.placementType,
                resourceName: row.performanceMaxPlacementView.resourceName,
                targetUrl: row.performanceMaxPlacementView.targetUrl,
                impressions: row.metrics.impressions
            };
            
            if (placement.targetUrl) uniqueUrls.add(placement.targetUrl);
            
            const checkedPlacement = await checkPlacementWithQualityAnalysis(placement);
            
            if (checkedPlacement.suggestion === QUALITY_LABELS.LOW_QUALITY) lowQualityCount++;
            if (checkedPlacement.blocklistMatch) blocklistMatchCount++;
            
            // Check if placement should be added to exclusions
            if (ADD_TO_ACCOUNT_EXCLUSIONS && 
                (checkedPlacement.suggestion === QUALITY_LABELS.LOW_QUALITY || 
                 checkedPlacement.score < AUTO_EXCLUSION_THRESHOLD)) {
                placementsForExclusion.push({
                    targetUrl: placement.targetUrl,
                    placementType: placement.placementType,
                    score: checkedPlacement.score,
                    reason: checkedPlacement.reason
                });
            }
            
            allResults.push([
                placement.campaignId || 'N/A',
                placement.targetUrl || 'N/A',
                placement.placementType || 'N/A',
                placement.impressions || 0
            ]);
            
            analysisResults.push([
                placement.campaignId || 'N/A',
                placement.targetUrl || 'N/A',
                placement.placementType || 'N/A',
                placement.impressions || 0,
                Math.round(checkedPlacement.score * 100) / 100,
                checkedPlacement.suggestion || 'UNKNOWN',
                checkedPlacement.reason || 'no reason provided',
                checkedPlacement.metaKeywords || 'no keywords extracted',
                checkedPlacement.flaggedTerms || ''
            ]);
        }
        
        // Process exclusions
        if (placementsForExclusion.length > 0) {
            console.log(`\nProcessing ${placementsForExclusion.length} placements for exclusion...`);
            await exclusionManager.addAccountLevelExclusions(placementsForExclusion);
        } else {
            console.log('\nNo placements qualified for exclusion.');
        }
        
        const endTime = new Date();
        const runtime = Math.round((endTime - startTime) / 1000);
        const slowUrls = globalThis.urlAssessor ? globalThis.urlAssessor.getSlowUrls() : [];
        const blocklistStats = globalThis.blocklistManager.getBlocklistStats();
        const spamKeywordsCount = globalThis.keywordConfig?.getSpamKeywords()?.length || 0;
        const exclusionResults = exclusionManager.getExclusionResults();
        
        console.log(`\n=== ANALYSIS SUMMARY ===`);
        console.log(`Total Unique URLs: ${uniqueUrls.size}`);
        console.log(`Total Placements: ${allResults.length}`);
        console.log(`Low Quality: ${lowQualityCount}`);
        console.log(`Blocklist Matches: ${blocklistMatchCount}`);
        console.log(`Exclusion Candidates: ${placementsForExclusion.length}`);
        console.log(`Actually Excluded: ${exclusionResults.stats.successful}`);
        console.log(`External Domains: ${blocklistStats.totalDomains}`);
        console.log(`External IPs: ${blocklistStats.totalIPs}`);
        console.log(`Spam Keywords: ${spamKeywordsCount}`);
        console.log(`Runtime: ${runtime}s`);
        
        outputToGoogleSheets(allResults, analysisResults, {
            uniqueUrls: uniqueUrls.size,
            totalPlacements: allResults.length,
            lowQualityCount,
            blocklistMatchCount,
            blocklistStats,
            spamKeywordsCount,
            exclusionCandidates: placementsForExclusion.length,
            exclusionResults,
            runtime,
            accountName,
            dateRange,
            slowUrls
        });
        
    } catch (error) {
        console.error('Error in main function:', error);
        throw error;
    }
}

function outputToGoogleSheets(allResults, analysisResults, summary) {
    try {
        const spreadsheet = SpreadsheetApp.openByUrl(SPREADSHEET_URL);
        
        // Clear and setup sheets
        let analysisSheet = spreadsheet.getSheetByName('PMAX placement exclusions') || 
                          spreadsheet.insertSheet('PMAX placement exclusions');
        analysisSheet.clear();
        
        const refreshDate = Utilities.formatDate(new Date(), AdsApp.currentAccount().getTimeZone(), 'yyyy-MM-dd HH:mm:ss');
        
        // Headers and summary
        analysisSheet.getRange(1, 1).setValue('PMAX Placement Evaluator with Auto-Exclusions');
        analysisSheet.getRange(2, 1).setValue(`Last Refresh: ${refreshDate}`);
        
        const summaryData = [
            ['SUMMARY'],
            [`Account: ${summary.accountName}`],
            [`Date Range: ${summary.dateRange.startDate} to ${summary.dateRange.endDate}`],
            [`Total Placements: ${summary.totalPlacements}`],
            [`Exclusion Recommendations: ${summary.lowQualityCount}`],
            [`Exclusion Candidates: ${summary.exclusionCandidates}`],
            [`Actually Excluded: ${summary.exclusionResults.stats.successful}`],
            [`Auto-Exclusions: ${ADD_TO_ACCOUNT_EXCLUSIONS ? (DRY_RUN_MODE ? 'DRY RUN' : 'ENABLED') : 'DISABLED'}`],
            [`Exclusion Rate: ${Math.round((summary.lowQualityCount / summary.totalPlacements) * 100)}%`],
            [`Runtime: ${summary.runtime}s`],
            [`External Blocklist Domains: ${summary.blocklistStats.totalDomains}`],
            [`External Blocklist IPs: ${summary.blocklistStats.totalIPs}`],
            [`Spam Keywords: ${summary.spamKeywordsCount}`],
            [`Blocklist Matches: ${summary.blocklistMatchCount}`],
            [`Source: https://github.com/J-Gute/pmax-words-to-exlcude/blob/main/spam-and-irrelevant-terms`]
        ];
        
        analysisSheet.getRange(4, 1, summaryData.length, 1).setValues(summaryData);
        
        // Analysis headers and data
        const headers = ['Campaign ID', 'URL', 'Placement Type', 'Impressions', 'Quality Score', 'Suggestion', 'Reason(s)', 'Content Analysis', 'Flagged Terms'];
        const headerRow = 20;
        
        analysisSheet.getRange(headerRow, 1, 1, headers.length).setValues([headers]);
        analysisSheet.getRange(headerRow, 1, 1, headers.length)
            .setFontWeight('bold')
            .setBackground('#A1A1A1')
            .setFontColor('black');
        
        if (analysisResults.length > 0) {
            analysisSheet.getRange(headerRow + 1, 1, analysisResults.length, headers.length).setValues(analysisResults);
        }
        
        // Add exclusion details if any
        if (summary.exclusionResults.excludedDomains.length > 0) {
            const exclusionHeaderRow = headerRow + analysisResults.length + 3;
            analysisSheet.getRange(exclusionHeaderRow, 1).setValue('EXCLUDED DOMAINS');
            analysisSheet.getRange(exclusionHeaderRow, 1).setFontWeight('bold');
            
            const exclusionHeaders = ['Domain', 'Score', 'Reason', 'Status'];
            analysisSheet.getRange(exclusionHeaderRow + 1, 1, 1, exclusionHeaders.length).setValues([exclusionHeaders]);
            analysisSheet.getRange(exclusionHeaderRow + 1, 1, 1, exclusionHeaders.length)
                .setFontWeight('bold')
                .setBackground('#FFE6E6');
            
            const exclusionData = summary.exclusionResults.excludedDomains.map(exc => [
                exc.domain,
                exc.score,
                exc.reason,
                exc.status
            ]);
            
            if (exclusionData.length > 0) {
                analysisSheet.getRange(exclusionHeaderRow + 2, 1, exclusionData.length, exclusionHeaders.length).setValues(exclusionData);
            }
        }
        
        // Set column widths
        [120, 300, 120, 100, 100, 120, 400, 400, 300].forEach((width, i) => {
            analysisSheet.setColumnWidth(i + 1, width);
        });
        
        console.log(`Results written to Google Sheets: ${analysisResults.length} rows`);
        
    } catch (error) {
        console.error('Error writing to Google Sheets:', error);
        throw error;
    }
}

function debug(obj) {
    console.log(JSON.stringify(obj, null, 2));
}
