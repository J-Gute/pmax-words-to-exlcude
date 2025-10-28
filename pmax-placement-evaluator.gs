/**
 * PMAX Placement Domain Analysis Script
 * Fetches blacklists, analyzes PMAX placements, and flags suspicious domains
 */

// Configuration
const CONFIG = {
  SPAM_KEYWORDS: 'https://raw.githubusercontent.com/J-Gute/pmax-placement-evaluator/refs/heads/main/spam-and-irrelevant-terms',
  WHITELIST_DOMAINS: 'https://raw.githubusercontent.com/J-Gute/pmax-placement-evaluator/refs/heads/main/whitelisted-domains.txt',
  SUSPICIOUS_TLDS: [
    'https://raw.githubusercontent.com/cbuijs/accomplist/main/suspicious-tlds/plain.black.tld.list',
    'https://raw.githubusercontent.com/2004gixxer600/BlockLists/refs/heads/main/MaliciousDomain.txt',
    'https://raw.githubusercontent.com/cbuijs/ut1/master/warez/domains',
    'https://raw.githubusercontent.com/cbuijs/accomplist/main/abuse-tlds/plain.black.domain.level-1.list.routedns',
    'https://raw.githubusercontent.com/cbuijs/accomplist/main/abuse-tlds/plain.black.domain.level-2.list.routedns',
    'https://raw.githubusercontent.com/cbuijs/accomplist/main/abuse-tlds/plain.black.domain.level-3.list.routedns',
    'https://raw.githubusercontent.com/cbuijs/accomplist/main/abuse-tlds/plain.black.domain.level-4.list.routedns'
  ],
  DOMAIN_BLOCKLIST: [
    'https://raw.githubusercontent.com/cbuijs/accomplist/main/easylist/optimized.black.domain.list',
    'https://raw.githubusercontent.com/cbuijs/accomplist/refs/heads/main/malicious-dom/optimized.black.domain.list',
    'https://raw.githubusercontent.com/cbuijs/accomplist/refs/heads/main/typosquat/optimized.black.domain.list',
    'https://raw.githubusercontent.com/cbuijs/accomplist/main/adult-themed/plain.black.domain.level-3.list',
    'https://raw.githubusercontent.com/cbuijs/accomplist/main/crypto/optimized.black.domain.list',
    'https://raw.githubusercontent.com/cbuijs/accomplist/main/gambling/optimized.black.domain.list',
    'https://raw.githubusercontent.com/cbuijs/accomplist/main/games/optimized.black.domain.list',
    'https://raw.githubusercontent.com/cbuijs/accomplist/main/streaming/optimized.black.domain.list',
    'https://raw.githubusercontent.com/cbuijs/accomplist/refs/heads/main/chris/amnestytech-investigations.list',
    'https://raw.githubusercontent.com/romainmarcoux/malicious-domains/refs/heads/main/full-domains-aa.txt',
    'https://raw.githubusercontent.com/Levi2288/AdvancedBlockList/refs/heads/main/Lists/adlist.txt',
    'https://raw.githubusercontent.com/Levi2288/AdvancedBlockList/refs/heads/main/Lists/spam.txt',
    'https://raw.githubusercontent.com/Levi2288/AdvancedBlockList/refs/heads/main/Lists/privacy.txt',
    'https://raw.githubusercontent.com/Levi2288/AdvancedBlockList/refs/heads/main/Lists/abuse.txt',
    'https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/domains/dga7.txt',
    'https://raw.githubusercontent.com/J-Gute/pmax-placement-evaluator/refs/heads/main/disw-mcc-exclusion-master-list',
  ],
  IP_BLOCKLIST: [
    'https://raw.githubusercontent.com/cbuijs/accomplist/refs/heads/main/malicious-ip/plain.black.ipcidr.list',
    'https://raw.githubusercontent.com/cbuijs/accomplist/refs/heads/main/malicious-ip/plain.black.ip4cidr.list',
    'https://raw.githubusercontent.com/stamparm/ipsum/refs/heads/master/levels/1.txt',
    'https://raw.githubusercontent.com/cbuijs/accomplist/refs/heads/main/chris/amnestytech-investigations-ips.list',
    'https://raw.githubusercontent.com/cbuijs/accomplist/refs/heads/main/chris/bad.abuse.list',
    'https://raw.githubusercontent.com/cbuijs/accomplist/refs/heads/main/chris/black.brazil.ip.list',
    'https://raw.githubusercontent.com/cbuijs/accomplist/refs/heads/main/chris/black.china.ip.list',
    'https://raw.githubusercontent.com/cbuijs/accomplist/refs/heads/main/chris/black.japan.ip.list',
    'https://raw.githubusercontent.com/cbuijs/accomplist/refs/heads/main/bogons/plain.black.ipcidr.list',
    'https://raw.githubusercontent.com/ShadowWhisperer/IPs/master/Malware/Hosting',
    'https://raw.githubusercontent.com/sefinek/Malicious-IP-Addresses/main/lists/main.txt'
  ],
  
  // Output configuration - REPLACE WITH YOUR SHEET URL
  SHEET_URL: 'URL here',
  DATES_BACK: 7,
  MIN_IMPRESSIONS: 2,
  DNS_BATCH_SIZE: 25,
  MAX_RETRIES: 3,
  
  // Analysis configuration
  SHORT_TERM_LENGTH: 6, 
  WORD_BOUNDARY_CHARS: ['.', '-', '_', '/', '?', '&', '=', '+'], 
  
  // Auto-exclude placement types
  AUTO_EXCLUDE_TYPES: ['YOUTUBE_VIDEO', 'MOBILE_APPLICATION'],
  
  // TLDs to filter out from suspicious lists (common legitimate TLDs)
  FILTER_OUT_TLDS: ['com', 'org', 'edu', 'de', 'uk', 'fr', 'jp', 'kr', 'us', 'es', 'ch', 'ir', 'pl'],
  
  OPR_API_KEY: 'API key here',
  OPR_BATCH_SIZE: 100, 
  OPR_ENABLED: true,
};

// Global variables for blacklists with source tracking
let blacklisted_domains = new Map(); 
let whitelisted_domains = new Set();
let suspicious_tlds = new Map(); 
let spam_keywords = [];
let blacklisted_ips = new Map(); // UPDATED: Now Map for source tracking
let domain_page_ranks = new Map(); 

/**
 * Extract list name from URL for reference
 */
function extractListName(url) {
  try {
    const cleanUrl = String(url).trim();
    
    if (cleanUrl.includes('raw.githubusercontent.com')) {
      const urlParts = cleanUrl.split('/');
      
      const mainIndex = urlParts.indexOf('main');
      
      if (mainIndex !== -1 && mainIndex < urlParts.length - 1) {
        const listName = urlParts[mainIndex + 1];
        return listName;
      }
      
      if (cleanUrl.includes('/malicious-ip/')) {
        return 'malicious-ip';
      }
      
      const filename = urlParts[urlParts.length - 1];
      return filename;
    }
    
    return cleanUrl;
  } catch (error) {
    console.warn('Error extracting list name from URL:', url, error);
    return String(url);
  }
}

/**
 * Create hyperlink for Google Sheets (returns formula as string)
 */
function createHyperlink(url, text) {
  return `=HYPERLINK("${url}","${text}")`;
}

/**
 * Main execution function
 */
function main() {
  const start_time = new Date();
  console.log('Starting PMAX Placement Analysis...');
  
  const timings = {};
  
  try {
    // Step 1: Fetch blacklists
    timings.blacklist_fetch = time_function(() => fetch_all_blacklists());
    
    // NEW: Validate IP matching functionality
    validate_ip_matching();
    
    // Step 2: Fetch PMAX placements
    timings.pmax_fetch = time_function(() => {
      return fetch_pmax_placements();
    });
    
    const placements = fetch_pmax_placements();
    
    // Step 3-8: Analyze placements
    timings.analysis = time_function(() => analyze_placements(placements));
    
    // NEW Step 9: Fetch Open Page Rank data
    timings.opr_fetch = time_function(() => fetch_open_page_rank_data(placements));
    
    // NEW Step 10: Apply Open Page Rank data
    timings.opr_apply = time_function(() => apply_open_page_rank_data(placements));
    
    // Step 11: Output results (previously step 9)
    timings.output = time_function(() => output_results(placements, timings, start_time));
    
    // Log summary
    log_summary(timings, placements.length, start_time);
    
  } catch (error) {
    console.error('Script execution failed:', error);
    throw error;
  }
}

/**
 * Load multiple IP blocklists with deduplication and source tracking
 */
function load_ip_blocklists() {
  console.log('Fetching IP blocklists...');
  const ips = new Map(); // ip -> source_url
  let total_loaded = 0;
  
  CONFIG.IP_BLOCKLIST.forEach((url, index) => {
    try {
      console.log(`Loading IP list ${index + 1}/${CONFIG.IP_BLOCKLIST.length} from: ${extractListName(url)}`);
      const response = fetchWithTimeout(url);
      
      if (response && response.getResponseCode() === 200) {
        let count = 0;
        
        response.getContentText().split('\n').forEach(line => {
          const trimmed = line.trim();
          if (trimmed && !trimmed.startsWith('#') && !trimmed.startsWith('//')) {
            // Extract IP from various formats
            let ip = trimmed;
            
            // Handle different formats:
            // - "1.2.3.4/32" (CIDR)
            // - "1.2.3.4 # comment" (IP with comment)
            // - "1.2.3.4	malware" (IP with tab-separated info)
            if (ip.includes(' ')) {
              ip = ip.split(' ')[0];
            }
            if (ip.includes('\t')) {
              ip = ip.split('\t')[0];
            }
            
            // Validate IP format (basic check for IPv4)
            if (ip.match(/^\d+\.\d+\.\d+\.\d+(\/\d+)?$/)) {
              if (!ips.has(ip)) {
                ips.set(ip, url);
                count++;
              }
            }
          }
        });
        
        console.log(`  Loaded ${count} IPs from ${extractListName(url)}`);
        total_loaded += count;
      } else {
        throw new Error(`HTTP ${response ? response.getResponseCode() : 'unknown'}`);
      }
    } catch (error) {
      console.warn(`Failed to load IP list from ${url}:`, error);
    }
  });
  
  console.log(`Total unique blacklisted IPs loaded: ${ips.size} (${total_loaded} total entries processed)`);
  return ips;
}

/**
 * Quick IP matching validation with source tracking
 */
function validate_ip_matching() {
  console.log('Validating IP matching with sample data...');
  
  const sample_tests = [
    '1.0.170.118',  // Should match exact IP
    '1.10.16.5',    // Should match /20 range
    '1.19.100.1',   // Should match /16 range
    '8.8.8.8',      // Should NOT match (Google DNS)
    '1.1.1.1'       // Should NOT match (Cloudflare DNS)
  ];
  
  let matches = 0;
  sample_tests.forEach(ip => {
    const is_blocked = is_ip_blacklisted(ip);
    if (is_blocked) {
      matches++;
      // Try to find which list blocked this IP
      let source = 'unknown';
      if (blacklisted_ips.has(ip)) {
        source = extractListName(blacklisted_ips.get(ip));
      } else if (blacklisted_ips.has(`${ip}/32`)) {
        source = extractListName(blacklisted_ips.get(`${ip}/32`));
      }
      console.log(`IP ${ip}: BLOCKED (from ${source})`);
    } else {
      console.log(`IP ${ip}: ALLOWED`);
    }
  });
  
  console.log(`IP validation complete: ${matches}/${sample_tests.length} test IPs were blocked`);
  console.log(`Total IP entries in blacklist: ${blacklisted_ips.size}`);
}

/**
 * Check if IP is blacklisted - UPDATED FOR MAP
 */
function is_ip_blacklisted(ip) {
  if (!ip || typeof ip !== 'string') {
    return false;
  }
  
  // Direct IP match (exact match)
  if (blacklisted_ips.has(ip)) {
    return true;
  }
  
  // Check for /32 notation match
  const exact_match = `${ip}/32`;
  if (blacklisted_ips.has(exact_match)) {
    return true;
  }
  
  // Check against all CIDR ranges in blacklist
  for (const [blocked_cidr, source] of blacklisted_ips) {
    if (blocked_cidr.includes('/')) {
      if (is_ip_in_cidr(ip, blocked_cidr)) {
        return true;
      }
    } else {
      // Handle entries without CIDR notation (treat as exact match)
      if (blocked_cidr === ip) {
        return true;
      }
    }
  }
  
  return false;
}

/**
 * Check if IP is in CIDR range - IMPROVED VERSION
 */
function is_ip_in_cidr(ip, cidr) {
  try {
    if (!cidr.includes('/')) {
      // If no CIDR notation, treat as exact match
      return ip === cidr;
    }
    
    const [network, prefix_length] = cidr.split('/');
    const prefix = parseInt(prefix_length);
    
    // Validate inputs
    if (isNaN(prefix) || prefix < 0 || prefix > 32) {
      return false;
    }
    
    // Convert IP addresses to integers
    const ip_parts = ip.split('.').map(Number);
    const network_parts = network.split('.').map(Number);
    
    // Validate IP format
    if (ip_parts.length !== 4 || network_parts.length !== 4) {
      return false;
    }
    
    if (ip_parts.some(part => isNaN(part) || part < 0 || part > 255) ||
        network_parts.some(part => isNaN(part) || part < 0 || part > 255)) {
      return false;
    }
    
    // Convert to 32-bit integers
    const ip_int = (ip_parts[0] << 24) + (ip_parts[1] << 16) + (ip_parts[2] << 8) + ip_parts[3];
    const network_int = (network_parts[0] << 24) + (network_parts[1] << 16) + (network_parts[2] << 8) + network_parts[3];
    
    // Create subnet mask
    const mask = prefix === 0 ? 0 : (0xFFFFFFFF << (32 - prefix)) >>> 0;
    
    // Check if IP is in the network
    return (ip_int & mask) === (network_int & mask);
    
  } catch (error) {
    console.warn(`Error checking CIDR ${cidr} for IP ${ip}:`, error);
    return false;
  }
}

/**
 * Get date range for GAQL query
 */
function getDateRange(daysBack) {
  const endDate = new Date();
  const startDate = new Date();
  startDate.setDate(startDate.getDate() - daysBack);
  
  return {
    startDate: formatDate(startDate),
    endDate: formatDate(endDate)
  };
}

/**
 * Format date for GAQL query (YYYY-MM-DD)
 */
function formatDate(date) {
  const year = date.getFullYear();
  const month = String(date.getMonth() + 1).padStart(2, '0');
  const day = String(date.getDate()).padStart(2, '0');
  return `${year}-${month}-${day}`;
}

/**
 * Fetch with timeout (synchronous version for Google Apps Script)
 */
function fetchWithTimeout(url, timeoutMs = 30000) {
  try {
    const response = UrlFetchApp.fetch(url, {
      method: 'GET',
      muteHttpExceptions: true,
      headers: {
        'User-Agent': 'Mozilla/5.0 (compatible; GoogleAdsBot/1.0)'
      }
    });
    return response;
  } catch (error) {
    console.error(`Fetch failed for ${url}:`, error);
    throw error;
  }
}

/**
 * Load spam keywords with deduplication
 */
function loadSpamKeywords() {
  try {
    console.log('Fetching spam keywords...');
    const response = fetchWithTimeout(CONFIG.SPAM_KEYWORDS);

    if (response && response.getResponseCode() === 200) {
      const keywords_set = new Set();
      
      response.getContentText()
        .split('\n')
        .forEach(line => {
          const keyword = line.trim().toLowerCase();
          if (keyword && !keyword.startsWith('#') && !keyword.startsWith('//')) {
            keywords_set.add(keyword);
          }
        });
      
      const keywords = Array.from(keywords_set);
      console.log(`Loaded ${keywords.length} unique spam keywords`);
      return keywords;
    } else {
      throw new Error(`HTTP ${response ? response.getResponseCode() : 'unknown'}`);
    }
  } catch (error) {
    console.warn('Failed to load spam keywords:', error);
    return [];
  }
}

/**
 * Load whitelist domains with deduplication
 */
function loadWhitelistDomains() {
  try {
    console.log('Fetching whitelist domains...');
    const response = fetchWithTimeout(CONFIG.WHITELIST_DOMAINS);

    if (response && response.getResponseCode() === 200) {
      const domains = new Set();
      
      response.getContentText()
        .split('\n')
        .forEach(line => {
          const domain = line.trim().toLowerCase();
          if (domain && !domain.startsWith('#') && !domain.startsWith('//')) {
            domains.add(domain);
          }
        });
      
      console.log(`Loaded ${domains.size} unique whitelist domains`);
      return domains;
    } else {
      throw new Error(`HTTP ${response ? response.getResponseCode() : 'unknown'}`);
    }
  } catch (error) {
    console.warn('Failed to load whitelist domains:', error);
    return new Set();
  }
}

/**
 * Extract TLD from line (expecting format: .tld)
 */
function extractTld(line) {
  const tld = line.trim().toLowerCase();
  
  if (!tld || tld.startsWith('#') || tld.startsWith('//')) {
    return null;
  }
  
  // Expecting format: .tld (e.g., .com, .tk, .0, .537z)
  if (tld.startsWith('.')) {
    const extracted_tld = tld.substring(1); // Remove the leading dot
    
    // Validate TLD (must be 1+ characters)
    if (extracted_tld.length >= 1) {
      return extracted_tld;
    }
  }
  
  return null;
}

/**
 * Load suspicious TLDs from multiple sources with deduplication and source tracking
 */
function loadSuspiciousTlds() {
  const tlds = new Map(); // tld -> source_url
  let total_loaded = 0;
  let filtered_count = 0;
  
  CONFIG.SUSPICIOUS_TLDS.forEach((url, index) => {
    try {
      console.log(`Fetching suspicious TLD list ${index + 1}/${CONFIG.SUSPICIOUS_TLDS.length}...`);
      const response = fetchWithTimeout(url);

      if (response && response.getResponseCode() === 200) {
        let tlds_added = 0;
        let tlds_filtered = 0;
        
        response.getContentText()
          .split('\n')
          .forEach(line => {
            const extracted_tld = extractTld(line);
            if (extracted_tld) {
              // Filter out specific legitimate TLDs
              if (CONFIG.FILTER_OUT_TLDS.includes(extracted_tld)) {
                tlds_filtered++;
                filtered_count++;
              } else {
                if (!tlds.has(extracted_tld)) {
                  tlds.set(extracted_tld, url);
                  tlds_added++;
                }
              }
            }
          });
        
        console.log(`Loaded ${tlds_added} unique TLDs from list ${index + 1} (filtered out ${tlds_filtered} legitimate TLDs)`);
        total_loaded += tlds_added;
      } else {
        throw new Error(`HTTP ${response ? response.getResponseCode() : 'unknown'}`);
      }
    } catch (error) {
      console.warn(`Failed to load TLD list ${index + 1}: ${url}`, error);
    }
  });
  
  // Add fallback TLDs if no lists loaded successfully (excluding filtered ones)
  if (tlds.size === 0) {
    console.warn('No TLD lists loaded successfully, adding fallback suspicious TLDs');
    const fallback_tlds = ['tk', 'ml', 'ga', 'cf', 'top', 'click', 'download', 'zip', 'review', 'country', 'stream'];
    fallback_tlds.forEach(tld => {
      if (!CONFIG.FILTER_OUT_TLDS.includes(tld)) {
        tlds.set(tld, 'fallback');
      }
    });
  }
  
  console.log(`Total unique suspicious TLDs loaded: ${tlds.size} (filtered out ${filtered_count} legitimate TLDs total)`);
  return tlds;
}

/**
 * Load domain blocklists with deduplication and source tracking
 */
function loadDomainBlocklists() {
  const domains = new Map(); // domain -> source_url
  
  CONFIG.DOMAIN_BLOCKLIST.forEach((url, index) => {
    try {
      console.log(`Fetching domain blocklist ${index + 1}/${CONFIG.DOMAIN_BLOCKLIST.length}...`);
      const response = fetchWithTimeout(url);

      if (response && response.getResponseCode() === 200) {
        let domains_added = 0;
        
        response.getContentText()
          .split('\n')
          .forEach(line => {
            const trimmed = line.trim().toLowerCase();
            if (trimmed && !trimmed.startsWith('#') && !trimmed.startsWith('//')) {
              // Handle different formats (hosts file, adblock, plain domains)
              let domain = trimmed;
              
              // Remove hosts file format (0.0.0.0 domain.com or 127.0.0.1 domain.com)
              if (domain.includes(' ')) {
                const parts = domain.split(' ');
                domain = parts[parts.length - 1];
              }
              
              // Remove adblock format (||domain.com^)
              domain = domain.replace(/^\|\|/, '').replace(/\^.*$/, '');
              
              // Validate domain format
              if (domain.includes('.') && !domain.includes('/') && domain.length > 3) {
                if (!domains.has(domain)) {
                  domains.set(domain, url);
                  domains_added++;
                }
              }
            }
          });
        
        console.log(`Loaded ${domains_added} unique domains from blocklist ${index + 1}`);
      } else {
        throw new Error(`HTTP ${response ? response.getResponseCode() : 'unknown'}`);
      }
    } catch (error) {
      console.warn(`Failed to load blocklist ${index + 1}: ${url}`, error);
    }
  });
  
  console.log(`Total unique domains loaded: ${domains.size}`);
  return domains;
}

/**
 * Fetch all blacklists and populate global variables
 */
function fetch_all_blacklists() {
  console.log('Fetching blacklists...');
  
  // Load all blacklists with deduplication and source tracking
  spam_keywords = loadSpamKeywords();
  whitelisted_domains = loadWhitelistDomains();
  suspicious_tlds = loadSuspiciousTlds();
  blacklisted_domains = loadDomainBlocklists();
  blacklisted_ips = load_ip_blocklists(); // UPDATED: Use new function
  
  console.log('\n=== BLACKLIST SUMMARY ===');
  console.log(`Spam keywords: ${spam_keywords.length} unique entries`);
  console.log(`Whitelisted domains: ${whitelisted_domains.size} unique entries`);
  console.log(`Suspicious TLDs: ${suspicious_tlds.size} unique entries`);
  console.log(`Blacklisted domains: ${blacklisted_domains.size} unique entries`);
  console.log(`Blacklisted IPs: ${blacklisted_ips.size} unique entries`);
  console.log('========================\n');
}

/**
 * Fetch PMAX placements using Google Ads API
 */
function fetch_pmax_placements() {
  console.log('Fetching PMAX placements...');
  
  try {
    // Get date range
    const dateRange = getDateRange(CONFIG.DATES_BACK);

    // Fetch placements
    const query = `
      SELECT campaign.id, performance_max_placement_view.display_name, 
             performance_max_placement_view.placement, performance_max_placement_view.placement_type, 
             performance_max_placement_view.resource_name, performance_max_placement_view.target_url, 
             metrics.impressions
      FROM performance_max_placement_view
      WHERE metrics.impressions > ${CONFIG.MIN_IMPRESSIONS}
        AND segments.date BETWEEN '${dateRange.startDate}' AND '${dateRange.endDate}'
        AND performance_max_placement_view.placement_type NOT IN ('YOUTUBE_CHANNEL', 'YOUTUBE_VIDEO')
      ORDER BY metrics.impressions DESC
    `;
    
    const placements = [];
    
    // Check if we're in MCC context
    if (typeof AdsManagerApp !== 'undefined') {
      // MCC context - iterate through accounts
      const account_iterator = AdsManagerApp.accounts().get();
      
      while (account_iterator.hasNext()) {
        const account = account_iterator.next();
        
        try {
          AdsManagerApp.select(account);
          const report = AdsApp.report(query);
          const rows = report.rows();
          
          while (rows.hasNext()) {
            const row = rows.next();
            
            placements.push({
              target_url: row['performance_max_placement_view.target_url'],
              placement: row['performance_max_placement_view.placement'],
              display_name: row['performance_max_placement_view.display_name'],
              placement_type: row['performance_max_placement_view.placement_type'],
              resource_name: row['performance_max_placement_view.resource_name'],
              campaign_id: row['campaign.id'],
              campaign_name: '',
              impressions: parseInt(row['metrics.impressions']),
              customer_id: account.getCustomerId(),
              customer_name: account.getName(),
              action: 'NEUTRAL',
              reason: '',
              reference_list: '',
              // NEW FIELDS for Open Page Rank
              page_rank: null,
              domain_rank: null,
              opr_status: null
            });
          }
        } catch (error) {
          console.warn(`Failed to fetch data for account ${account.getCustomerId()}:`, error);
        }
      }
    } else {
      // Single account context
      try {
        const report = AdsApp.report(query);
        const rows = report.rows();
        
        while (rows.hasNext()) {
          const row = rows.next();
          
          placements.push({
            target_url: row['performance_max_placement_view.target_url'],
            placement: row['performance_max_placement_view.placement'],
            display_name: row['performance_max_placement_view.display_name'],
            placement_type: row['performance_max_placement_view.placement_type'],
            resource_name: row['performance_max_placement_view.resource_name'],
            campaign_id: row['campaign.id'],
            campaign_name: '', // Not available in this query structure
            impressions: parseInt(row['metrics.impressions']),
            customer_id: AdsApp.currentAccount().getCustomerId(),
            customer_name: AdsApp.currentAccount().getName(),
            action: 'NEUTRAL',
            reason: '',
            reference_list: ''
          });
        }
      } catch (error) {
        console.error('Failed to fetch data from single account:', error);
        throw error;
      }
    }
    
    console.log(`Fetched ${placements.length} placements`);
    return placements;
    
  } catch (error) {
    console.error('Failed to fetch PMAX placements:', error);
    throw error;
  }
}

/**
 * Fetch Open Page Rank data for unique domains
 */
function fetch_open_page_rank_data(placements) {
  if (!CONFIG.OPR_ENABLED || !CONFIG.OPR_API_KEY || CONFIG.OPR_API_KEY === 'YOUR-API-KEY-HERE') {
    console.log('Open Page Rank API disabled or not configured');
    return;
  }
  
  console.log('Fetching Open Page Rank data...');
  
  // Extract unique domains from placements
  const unique_domains = new Set();
  placements.forEach(placement => {
    if (placement.target_url) {
      const domain = extract_domain(placement.target_url);
      if (domain) {
        unique_domains.add(domain);
      }
    }
  });
  
  const domains_array = Array.from(unique_domains);
  console.log(`Found ${domains_array.length} unique domains for OPR lookup`);
  
  // Process domains in batches
  const batches = [];
  for (let i = 0; i < domains_array.length; i += CONFIG.OPR_BATCH_SIZE) {
    batches.push(domains_array.slice(i, i + CONFIG.OPR_BATCH_SIZE));
  }
  
  batches.forEach((batch, index) => {
    console.log(`Processing OPR batch ${index + 1}/${batches.length} (${batch.length} domains)`);
    
    try {
      const opr_data = call_open_page_rank_api(batch);
      
      if (opr_data && opr_data.response) {
        opr_data.response.forEach(domain_data => {
          domain_page_ranks.set(domain_data.domain, {
            page_rank_integer: domain_data.page_rank_integer || 0,
            page_rank_decimal: domain_data.page_rank_decimal || 0,
            rank: domain_data.rank || null,
            status_code: domain_data.status_code || 0,
            error: domain_data.error || ''
          });
        });
      }
      
      // Rate limiting between batches
      if (index < batches.length - 1) {
        Utilities.sleep(1000); // 1 second delay between batches
      }
      
    } catch (error) {
      console.warn(`Failed to fetch OPR data for batch ${index + 1}:`, error);
    }
  });
  
  console.log(`Successfully fetched OPR data for ${domain_page_ranks.size} domains`);
}

/**
 * Call Open Page Rank API for a batch of domains
 */
function call_open_page_rank_api(domains) {
  const base_url = 'https://openpagerank.com/api/v1.0/getPageRank';
  
  // Build query parameters
  const query_params = domains.map(domain => `domains[]=${encodeURIComponent(domain)}`).join('&');
  const full_url = `${base_url}?${query_params}`;
  
  try {
    const response = UrlFetchApp.fetch(full_url, {
      method: 'GET',
      headers: {
        'API-OPR': CONFIG.OPR_API_KEY,
        'User-Agent': 'GoogleAdsScript/1.0'
      },
      muteHttpExceptions: true
    });
    
    if (response.getResponseCode() === 200) {
      return JSON.parse(response.getContentText());
    } else {
      throw new Error(`HTTP ${response.getResponseCode()}: ${response.getContentText()}`);
    }
    
  } catch (error) {
    console.error('Open Page Rank API call failed:', error);
    throw error;
  }
}

/**
 * Apply Open Page Rank data to placements
 */
function apply_open_page_rank_data(placements) {
  if (domain_page_ranks.size === 0) {
    console.log('No Open Page Rank data available');
    return;
  }
  
  console.log('Applying Open Page Rank data to placements...');
  
  placements.forEach(placement => {
    if (placement.target_url) {
      const domain = extract_domain(placement.target_url);
      if (domain && domain_page_ranks.has(domain)) {
        const opr_data = domain_page_ranks.get(domain);
        
        placement.page_rank = opr_data.page_rank_decimal;
        placement.domain_rank = opr_data.rank;
        placement.opr_status = opr_data.status_code === 200 ? 'Found' : 'Not Found';
      }
    }
  });
}

/**
 * Analyze all placements and flag suspicious ones
 */
function analyze_placements(placements) {
  console.log('Analyzing placements...');
  
  placements.forEach(placement => {
    // Step 3: Check placement type first (auto-exclude apps and YouTube)
    if (check_auto_exclude_placement_type(placement)) return;
    
    if (!placement.target_url) return;
    
    const domain = extract_domain(placement.target_url);
    if (!domain) return;
    
    // Step 4: Check if whitelisted (FIRST PRIORITY for domains)
    if (check_whitelisted_domain(domain, placement)) return;
    
    // Step 5: Check against blacklisted domains
    if (check_blacklisted_domain(domain, placement)) return;
    
    // Step 6: Check suspicious TLDs
    if (check_suspicious_tld(domain, placement)) return;
    
    // Step 7: Check spam keywords with improved matching
    if (check_spam_keywords_improved(domain, placement)) return;
  });
  
  // Step 8: DNS/IP checks (batched)
  if (blacklisted_ips.size > 0) {
    perform_dns_checks(placements.filter(p => p.action === 'NEUTRAL'));
  } else {
    console.log('Skipping DNS checks - no IP blacklist loaded');
  }
}

/**
 * Check if placement type should be auto-excluded
 */
function check_auto_exclude_placement_type(placement) {
  if (CONFIG.AUTO_EXCLUDE_TYPES.includes(placement.placement_type)) {
    placement.action = 'EXCLUDE';
    placement.reason = 'non-website placement; exclude apps + youtube by default';
    placement.reference_list = '';
    return true;
  }
  return false;
}

/**
 * Extract domain from URL
 */
function extract_domain(url) {
  try {
    // Remove protocol if present
    let domain = url.replace(/^https?:\/\//, '');
    
    // Remove path, query, and fragment
    domain = domain.split('/')[0].split('?')[0].split('#')[0];
    
    // Remove port if present
    domain = domain.split(':')[0];
    
    return domain.toLowerCase();
  } catch (error) {
    console.warn(`Failed to extract domain from: ${url}`);
    return null;
  }
}

/**
 * Check if domain is whitelisted (FIRST PRIORITY)
 */
function check_whitelisted_domain(domain, placement) {
  if (whitelisted_domains.has(domain)) {
    placement.action = 'KEEP';
    placement.reason = 'whitelisted domain';
    placement.reference_list = '';
    return true;
  }
  
  // Check subdomains against whitelist
  const parts = domain.split('.');
  for (let i = 1; i < parts.length; i++) {
    const subdomain = parts.slice(i).join('.');
    if (whitelisted_domains.has(subdomain)) {
      placement.action = 'KEEP';
      placement.reason = 'whitelisted domain (parent)';
      placement.reference_list = '';
      return true;
    }
  }
  
  return false;
}

/**
 * Check if domain is blacklisted
 */
function check_blacklisted_domain(domain, placement) {
  if (blacklisted_domains.has(domain)) {
    const source_url = blacklisted_domains.get(domain);
    const list_name = extractListName(source_url);
    placement.action = 'EXCLUDE';
    placement.reason = `blacklisted domain; reported in ${list_name}`;
    placement.reference_list = createHyperlink(source_url, list_name);
    return true;
  }
  
  // Check subdomains
  const parts = domain.split('.');
  for (let i = 1; i < parts.length; i++) {
    const subdomain = parts.slice(i).join('.');
    if (blacklisted_domains.has(subdomain)) {
      const source_url = blacklisted_domains.get(subdomain);
      const list_name = extractListName(source_url);
      placement.action = 'EXCLUDE';
      placement.reason = `blacklisted domain (parent); reported in ${list_name}`;
      placement.reference_list = createHyperlink(source_url, list_name);
      return true;
    }
  }
  
  return false;
}

/**
 * Check if TLD is suspicious
 */
function check_suspicious_tld(domain, placement) {
  const tld = domain.split('.').pop();
  
  if (suspicious_tlds.has(tld)) {
    const source_url = suspicious_tlds.get(tld);
    const list_name = extractListName(source_url);
    placement.action = 'EXCLUDE';
    placement.reason = `suspicious TLD: ${tld}; reported in ${list_name}`;
    placement.reference_list = createHyperlink(source_url, list_name);
    return true;
  }
  
  return false;
}

/**
 * Check if a character is a word boundary
 */
function isWordBoundary(char) {
  return CONFIG.WORD_BOUNDARY_CHARS.includes(char) || /[^a-z0-9]/i.test(char);
}

/**
 * Check if keyword match is valid based on word boundaries
 */
function isValidKeywordMatch(domain, keyword, startIndex) {
  const keywordLength = keyword.length;
  const endIndex = startIndex + keywordLength;
  
  // For short keywords (<=6 chars), require word boundaries
  if (keywordLength <= CONFIG.SHORT_TERM_LENGTH) {
    const beforeChar = startIndex > 0 ? domain[startIndex - 1] : '';
    const afterChar = endIndex < domain.length ? domain[endIndex] : '';
    
    // Check if keyword is at word boundary (start/end of domain or separated by boundary chars)
    const atStart = startIndex === 0 || isWordBoundary(beforeChar);
    const atEnd = endIndex === domain.length || isWordBoundary(afterChar);
    
    return atStart && atEnd;
  }
  
  // For longer keywords, allow substring matches
  return true;
}

/**
 * Improved spam keyword checking with word boundary validation
 */
function check_spam_keywords_improved(domain, placement) {
  if (spam_keywords.length === 0) return false;
  
  const found_terms = [];
  const normalized_domain = domain.toLowerCase();
  
  // Check each spam keyword
  spam_keywords.forEach(keyword => {
    const normalized_keyword = keyword.toLowerCase().trim();
    
    if (normalized_keyword.length === 0) return;
    
    // Find all occurrences of the keyword in the domain
    let index = normalized_domain.indexOf(normalized_keyword);
    while (index !== -1) {
      // Check if this match is valid based on word boundaries
      if (isValidKeywordMatch(normalized_domain, normalized_keyword, index)) {
        found_terms.push(keyword);
        break; // Found valid match, no need to check more occurrences of this keyword
      }
      
      // Look for next occurrence
      index = normalized_domain.indexOf(normalized_keyword, index + 1);
    }
  });
  
  // Remove duplicates
  const unique_terms = [...new Set(found_terms)];
  
  if (unique_terms.length > 0) {
    const list_name = extractListName(CONFIG.SPAM_KEYWORDS);
    placement.action = 'EXCLUDE';
    placement.reason = `terms detected: ${unique_terms.join(', ')}; reported in ${list_name}`;
    placement.reference_list = createHyperlink(CONFIG.SPAM_KEYWORDS, list_name);
    return true;
  }
  
  return false;
}

/**
 * Simplified DNS resolver class - UPDATED VERSION
 */
class SimpleDNSResolver {
  resolve_domain_ips(domain) {
    const dns_info = {
      success: false,
      ip_addresses: [],
      is_blacklisted_ip: false,
      blacklisted_ips: [],
      error: null
    };
    
    try {
      const response = UrlFetchApp.fetch(`https://1.1.1.1/dns-query?name=${domain}&type=A`, {
        method: 'GET',
        headers: { 'Accept': 'application/dns-json' },
        muteHttpExceptions: true
      });
      
      if (response.getResponseCode() === 200) {
        const dns_data = JSON.parse(response.getContentText());
        
        if (dns_data.Status === 0 && dns_data.Answer) {
          dns_info.success = true;
          
          // Extract IP addresses from A records only
          dns_data.Answer
            .filter(record => record.type === 1) // A records only
            .forEach(record => {
              const ip = record.data;
              dns_info.ip_addresses.push(ip);
              
              // Check if this IP is blacklisted
              if (is_ip_blacklisted(ip)) {
                dns_info.is_blacklisted_ip = true;
                dns_info.blacklisted_ips.push(ip);
              }
            });
            
        } else {
          dns_info.error = `DNS query failed: Status ${dns_data.Status}`;
        }
      } else {
        dns_info.error = `HTTP ${response.getResponseCode()}`;
      }
    } catch (error) {
      dns_info.error = error.message;
    }
    
    return dns_info;
  }
}

/**
 * Perform DNS checks in batches - UPDATED VERSION
 */
function perform_dns_checks(placements) {
  console.log(`Performing DNS checks for ${placements.length} placements...`);
  
  const dns_resolver = new SimpleDNSResolver();
  const batches = [];
  
  for (let i = 0; i < placements.length; i += CONFIG.DNS_BATCH_SIZE) {
    batches.push(placements.slice(i, i + CONFIG.DNS_BATCH_SIZE));
  }
  
  batches.forEach((batch, index) => {
    console.log(`Processing DNS batch ${index + 1}/${batches.length}`);
    
    batch.forEach(placement => {
      const domain = extract_domain(placement.target_url);
      if (!domain) return;
      
      try {
        const dns_info = dns_resolver.resolve_domain_ips(domain);
        
        if (dns_info.is_blacklisted_ip && dns_info.blacklisted_ips.length > 0) {
          placement.action = 'EXCLUDE';
          // Format only the blacklisted IPs with line breaks if multiple
          const ip_list = dns_info.blacklisted_ips.length > 1 
            ? dns_info.blacklisted_ips.join('\n')
            : dns_info.blacklisted_ips[0];
          
          // Get the first IP blocklist URL for reference
          const reference_url = CONFIG.IP_BLOCKLIST[0];
          const list_name = extractListName(reference_url);
          
          placement.reason = `blacklisted IP:\n${ip_list}; reported in ${list_name}`;
          placement.reference_list = createHyperlink(reference_url, list_name);
        }
      } catch (error) {
        console.warn(`DNS lookup failed for ${domain}:`, error);
      }
    });
    
    // Rate limiting
    if (index < batches.length - 1) {
      Utilities.sleep(1000);
    }
  });
}

/**
 * Get current date and time in EST
 */
function get_current_est_datetime() {
  const now = new Date();
  const est_offset = -5; // EST is UTC-5
  const est_time = new Date(now.getTime() + (est_offset * 60 * 60 * 1000));
  
  return est_time.toLocaleString('en-US', {
    timeZone: 'America/New_York',
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit'
  });
}

/**
 * Output results to Google Sheet with summary info
 */
function output_results(placements, timings, start_time) {
  console.log('Outputting results...');
  
  if (!CONFIG.SHEET_URL || CONFIG.SHEET_URL === 'YOUR_SHEET_URL_HERE') {
    console.error('Sheet URL not configured - please update CONFIG.SHEET_URL');
    return;
  }
  
  try {
    const spreadsheet = SpreadsheetApp.openByUrl(CONFIG.SHEET_URL);
    
    // Create or get main analysis sheet
    let analysis_sheet = spreadsheet.getSheetByName('Analysis');
    if (!analysis_sheet) {
      analysis_sheet = spreadsheet.insertSheet('Analysis');
    }
    
    // Create or get raw data sheet (hidden)
    let raw_sheet = spreadsheet.getSheetByName('gaql_output');
    if (!raw_sheet) {
      raw_sheet = spreadsheet.insertSheet('gaql_output');
      raw_sheet.hideSheet();
    }
    
    // Output raw data to gaql_output sheet
    output_raw_data(raw_sheet, placements);
    
    // Output analysis to main sheet
    output_analysis_data(analysis_sheet, placements, timings, start_time);
    
  } catch (error) {
    console.error('Failed to output results:', error);
    throw error;
  }
}

/**
 * Output raw GAQL data to hidden sheet
 */
function output_raw_data(sheet, placements) {
  sheet.clear();
  
  const headers = [
    'Target URL',
    'Placement',
    'Display Name',
    'Placement Type',
    'Resource Name',
    'Campaign ID',
    'Impressions',
    'Customer ID',
    'Customer Name',
    'Page Rank',
    'Domain Rank',
    'OPR Status'
  ];
  
  sheet.getRange(1, 1, 1, headers.length).setValues([headers]);
  
  const data = placements.map(placement => [
    placement.target_url,
    placement.placement,
    placement.display_name,
    placement.placement_type,
    placement.resource_name,
    placement.campaign_id,
    placement.impressions,
    placement.customer_id,
    placement.customer_name,
    placement.page_rank || '',
    placement.domain_rank || '',
    placement.opr_status || ''
  ]);
  
  if (data.length > 0) {
    sheet.getRange(2, 1, data.length, headers.length).setValues(data);
  }
  
  sheet.getRange(1, 1, 1, headers.length).setFontWeight('bold');
  sheet.autoResizeColumns(1, headers.length);
}

/**
 * Output analysis data with improved formatting
 */
function output_analysis_data(sheet, placements, timings, start_time) {
  sheet.clear();
  
  const total_time = new Date() - start_time;
  const excluded_count = get_excluded_count(placements);
  const keep_count = get_keep_count(placements);
  const current_datetime = get_current_est_datetime();
  const dateRange = getDateRange(CONFIG.DATES_BACK);
  
  // Get unique customer info
  const unique_customers = [...new Set(placements.map(p => `${p.customer_name} - ${p.customer_id}`))];
  const customer_display = unique_customers.length > 0 ? unique_customers.join(', ') : 'No accounts found';
  
  // Summary header - all in column A, rows 1-7
  const summary_data = [
    [`Account: ${customer_display}`],
    [`Script Last Refresh: ${current_datetime}`],
    [`Script Total Runtime: ${(total_time / 1000).toFixed(2)} seconds`],
    [`Date Range: ${dateRange.startDate} to ${dateRange.endDate}`],
    [`Total PMAX Placements: ${placements.length} | Recommended Exclusions: ${excluded_count} | Whitelisted: ${keep_count}`],
    [`Blacklist Stats: ${spam_keywords.length} keywords, ${blacklisted_domains.size} domains, ${suspicious_tlds.size} TLDs`],
    [`Open Page Rank: ${domain_page_ranks.size} domains analyzed | API Status: ${CONFIG.OPR_ENABLED ? 'Enabled' : 'Disabled'}`]
  ];
  
  // Write summary to column A, rows 1-7
  summary_data.forEach((row, index) => {
    sheet.getRange(index + 1, 1, 1, 1).setValue(row[0]);
  });
  
  // Format summary rows with specific styling
  sheet.getRange(1, 1, 1, 1).setFontWeight('bold'); // Row 1: Bold
  sheet.getRange(2, 1, 4, 1).setFontStyle('italic'); // Rows 2-5: Italic
  
  // Data headers starting after summary (row 9)
  const header_row = 9;
  const headers = [
    'Campaign ID',
    'Placement Type',
    'Placement',
    'Impr.',
    'Display Name',
    'Action',
    'Reason',
    'Reference List',
    'Page Rank',
    'Domain Rank'
  ];
  
  sheet.getRange(header_row, 1, 1, headers.length).setValues([headers]);
  
  // Format headers with grey background and text wrap
  const header_range = sheet.getRange(header_row, 1, 1, headers.length);
  header_range.setFontWeight('bold');
  header_range.setBackground('#d9d9d9');
  header_range.setWrap(true);
  
  // Data rows - WITH OPEN PAGE RANK DATA
  if (placements.length > 0) {
    const data = placements.map(placement => [
      placement.campaign_id || '',
      placement.placement_type || '',
      placement.target_url || '',
      placement.impressions || 0,
      placement.display_name || '',
      placement.action || 'NEUTRAL',
      placement.reason || '',
      placement.reference_list || '',
      placement.page_rank || '',
      placement.domain_rank || ''
    ]);
    
    sheet.getRange(header_row + 1, 1, data.length, headers.length).setValues(data);
    
    // Add conditional formatting for EXCLUDE rows (Action is column 6)
    const action_range = sheet.getRange(header_row + 1, 6, data.length, 1);
    const exclude_rule = SpreadsheetApp.newConditionalFormatRule()
      .whenTextEqualTo('EXCLUDE')
      .setBackground('#ffcccc')
      .setRanges([action_range])
      .build();
    
    // Add conditional formatting for KEEP rows
    const keep_rule = SpreadsheetApp.newConditionalFormatRule()
      .whenTextEqualTo('KEEP')
      .setBackground('#ccffcc')
      .setRanges([action_range])
      .build();
    
    const rules = sheet.getConditionalFormatRules();
    rules.push(exclude_rule);
    rules.push(keep_rule);
    sheet.setConditionalFormatRules(rules);
    
    // Enable text wrapping for the Reason column (column 7)
    const reason_range = sheet.getRange(header_row + 1, 7, data.length, 1);
    reason_range.setWrap(true);
    
    // Set specific column widths
    sheet.setColumnWidth(7, 300); // Make Reason column wider (300 pixels)
    sheet.setColumnWidth(8, 200); // Set Reference List column width (200 pixels)
    sheet.setColumnWidth(2, 120); // Set Placement Type column width (120 pixels)
    sheet.setColumnWidth(4, 80);  // Set Impr. column width (80 pixels)
    sheet.setColumnWidth(9, 80);  // Set Page Rank column width (80 pixels)
    sheet.setColumnWidth(10, 100); // Set Domain Rank column width (100 pixels)
  }
  
  // Auto-resize most columns but preserve custom widths for specific columns
  for (let i = 1; i <= headers.length; i++) {
    if (![2, 4, 7, 8, 9, 10].includes(i)) {
      sheet.autoResizeColumn(i);
    }
  }
  
  console.log(`Output ${placements.length} rows to analysis sheet`);
}

/**
 * Utility functions
 */
function time_function(func) {
  const start = new Date();
  const result = func();
  return new Date() - start;
}

function escape_regex(string) {
  return string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function log_summary(timings, total_placements, start_time) {
  const total_time = new Date() - start_time;
  const excluded_count = get_excluded_count([]);
  
  console.log('\n=== EXECUTION SUMMARY ===');
  console.log(`Total execution time: ${(total_time / 1000).toFixed(2)}s`);
  console.log(`Blacklist fetch: ${(timings.blacklist_fetch / 1000).toFixed(2)}s`);
  console.log(`PMAX fetch: ${(timings.pmax_fetch / 1000).toFixed(2)}s`);
  console.log(`Analysis: ${(timings.analysis / 1000).toFixed(2)}s`);
  console.log(`Output: ${(timings.output / 1000).toFixed(2)}s`);
  console.log(`Total placements analyzed: ${total_placements}`);
  console.log(`Placements flagged for exclusion: ${excluded_count}`);
  console.log('========================\n');
}

/**
 * Helper function to get excluded placements count
 */
function get_excluded_count(placements) {
  return placements.filter(p => p.action === 'EXCLUDE').length;
}

/**
 * Helper function to get whitelisted placements count
 */
function get_keep_count(placements) {
  return placements.filter(p => p.action === 'KEEP').length;
}

/**
 * Test function for development
 */
function test_script() {
  console.log('Running test with sample data...');
  
  // Test domain extraction
  console.log('Testing domain extraction...');
  console.log(extract_domain('https://www.example.com/path?query=1'));
  
  // Test keyword matching
  console.log('Testing keyword matching...');
  console.log('infantslab.com with "infant":', isValidKeywordMatch('infantslab.com', 'infant', 0));
  console.log('infantslab.com with "ants":', isValidKeywordMatch('infantslab.com', 'ants', 3));
  console.log('indianexpress.com with "dia":', isValidKeywordMatch('indianexpress.com', 'dia', 2));
  console.log('test-domain.com with "domain":', isValidKeywordMatch('test-domain.com', 'domain', 5));
  
  // Test auto-exclude placement types
  console.log('Testing auto-exclude placement types...');
  const test_placement = { placement_type: 'YOUTUBE_VIDEO', action: 'NEUTRAL', reason: '', reference_list: '' };
  console.log('YouTube video should be excluded:', check_auto_exclude_placement_type(test_placement));
  
  // Test TLD extraction and filtering
  console.log('Testing TLD extraction and filtering...');
  console.log('Should extract tk:', extractTld('.tk'));
  console.log('Should extract com:', extractTld('.com'));
  console.log('Should filter com:', CONFIG.FILTER_OUT_TLDS.includes('com'));
  console.log('Should not filter tk:', CONFIG.FILTER_OUT_TLDS.includes('tk'));
  
  // Test list name extraction
  console.log('Testing list name extraction...');
  console.log('Extract from cbuijs URL:', extractListName('https://raw.githubusercontent.com/cbuijs/accomplist/main/suspicious-tlds/plain.black.tld.list'));
  console.log('Extract from J-Gute URL:', extractListName('https://raw.githubusercontent.com/J-Gute/pmax-words-to-exlcude/main/spam-and-irrelevant-terms'));
}
