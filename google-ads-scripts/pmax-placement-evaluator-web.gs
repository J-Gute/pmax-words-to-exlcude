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
    'https://raw.githubusercontent.com/hagezi/dns-blocklists/refs/heads/main/wildcard/fake-onlydomains.txt',
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
    'https://raw.githubusercontent.com/cbuijs/accomplist/refs/heads/main/chris/black.hong_kong.ip.list',
    'https://raw.githubusercontent.com/cbuijs/accomplist/refs/heads/main/chris/black.india.ip.list',
    'https://raw.githubusercontent.com/cbuijs/accomplist/refs/heads/main/chris/black.philippines.ip.list',
    'https://raw.githubusercontent.com/cbuijs/accomplist/refs/heads/main/chris/black.russia.ip.list',
    'https://raw.githubusercontent.com/cbuijs/accomplist/refs/heads/main/chris/black.japan.ip.list',
    'https://raw.githubusercontent.com/cbuijs/accomplist/refs/heads/main/bogons/plain.black.ipcidr.list',
    'https://raw.githubusercontent.com/ShadowWhisperer/IPs/master/Malware/Hosting',
    'https://raw.githubusercontent.com/sefinek/Malicious-IP-Addresses/main/lists/main.txt'
  ],
  SHEET_URL: 'URL here',
  DATES_BACK: 10,
  MIN_IMPRESSIONS: 2,
  DNS_BATCH_SIZE: 25,
  MAX_RETRIES: 3,
  SHORT_TERM_LENGTH: 6,
  WORD_BOUNDARY_CHARS: ['.', '-', '_', '/', '?', '&', '=', '+'],
  AUTO_EXCLUDE_TYPES: ['YOUTUBE_VIDEO', 'MOBILE_APPLICATION'],
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
let blacklisted_ips = new Map();
let domain_page_ranks = new Map();

/**
 * Enhanced dynamic list name extraction with intelligent naming based on repo and category
 */
function extractListName(url) {
  try {
    const cleanUrl = String(url).trim();
    
    // Handle non-GitHub URLs
    if (!cleanUrl.includes('raw.githubusercontent.com') && !cleanUrl.includes('jsdelivr.net')) {
      return cleanUrl;
    }
    
    // Handle jsdelivr URLs
    if (cleanUrl.includes('jsdelivr.net')) {
      const jsdelivr_match = cleanUrl.match(/cdn\.jsdelivr\.net\/gh\/([^\/]+)\/([^@\/]+)@?[^\/]*\/(.+)/);
      if (jsdelivr_match) {
        const [, owner, repo, path] = jsdelivr_match;
        const category = path.split('/')[0] || 'unknown';
        const filename = path.split('/').pop() || 'unknown';
        return generateDynamicName(owner, repo, category, filename, 'jsdelivr');
      }
    }
    
    // Handle GitHub URLs
    const urlParts = cleanUrl.split('/');
    if (urlParts.length < 6) return cleanUrl;
    
    const repo_owner = urlParts[3] || 'unknown';
    const repo_name = urlParts[4] || 'unknown';
    let category, filename;
    
    // Handle different GitHub URL patterns
    if (cleanUrl.includes('/refs/heads/main/') || cleanUrl.includes('/refs/heads/master/')) {
      // Pattern: /refs/heads/main/ or /refs/heads/master/
      const pathStart = cleanUrl.includes('/refs/heads/main/') ?
        cleanUrl.indexOf('/refs/heads/main/') + '/refs/heads/main/'.length :
        cleanUrl.indexOf('/refs/heads/master/') + '/refs/heads/master/'.length;
      const remainingPath = cleanUrl.substring(pathStart);
      const pathParts = remainingPath.split('/');
      category = pathParts[0] || 'unknown';
      filename = pathParts[pathParts.length - 1] || 'unknown';
    } else if (cleanUrl.includes('/master/') || cleanUrl.includes('/main/')) {
      // Pattern: /master/ or /main/ (without refs/heads)
      const branchIndex = cleanUrl.includes('/master/') ? 
        cleanUrl.indexOf('/master/') + '/master/'.length :
        cleanUrl.indexOf('/main/') + '/main/'.length;
      const remainingPath = cleanUrl.substring(branchIndex);
      const pathParts = remainingPath.split('/');
      category = pathParts[0] || 'unknown';
      filename = pathParts[pathParts.length - 1] || 'unknown';
    } else {
      // Fallback pattern matching
      const mainIndex = urlParts.findIndex(part => part === 'main' || part === 'master');
      if (mainIndex !== -1 && mainIndex < urlParts.length - 1) {
        category = urlParts[mainIndex + 1] || 'unknown';
        filename = urlParts[urlParts.length - 1] || 'unknown';
      } else {
        // Last resort - use last two parts
        category = urlParts[urlParts.length - 2] || 'unknown';
        filename = urlParts[urlParts.length - 1] || 'unknown';
      }
    }
    
    return generateDynamicName(repo_owner, repo_name, category, filename, 'github');
  } catch (error) {
    console.warn('Error extracting list name from URL:', url, error);
    // Return a simplified name instead of the full URL
    try {
      const urlParts = String(url).split('/');
      if (urlParts.length >= 5) {
        const owner = urlParts[3] || 'unknown';
        const repo = urlParts[4] || 'unknown';
        return `${capitalizeFirst(owner)} ${capitalizeFirst(repo)}`;
      }
    } catch (fallbackError) {
      // Final fallback
      return 'Unknown Source';
    }
    return 'Unknown Source';
  }
}

/**
 * Generate dynamic names based on repository patterns and content analysis
 */
function generateDynamicName(owner, repo, category, filename, platform) {
  const normalizedOwner = owner.toLowerCase();
  const normalizedRepo = repo.toLowerCase();
  const normalizedCategory = category.toLowerCase();
  const normalizedFilename = filename.toLowerCase();
  const ownerPatterns = {
    'cbuijs': 'Accomplist',
    'j-gute': 'di sw',
    'levi2288': 'AdvancedBlockList',
    'romainmarcoux': 'Marcoux Security',
    'stamparm': 'IPsum',
    'shadowwhisperer': 'ShadowWhisperer',
    'sefinek': 'Sefinek Security',
    '2004gixxer600': 'Gixxer BlockLists',
    'hagezi': 'HaGeZi'
  };
  const categoryPatterns = {
    'easylist': 'EasyList Domains',
    'malicious-dom': 'Malicious Domains',
    'typosquat': 'Typosquatting Domains',
    'adult-themed': 'Adult Content Domains',
    'crypto': 'Crypto Scam Domains',
    'gambling': 'Gambling Domains',
    'games': 'Gaming Domains',
    'streaming': 'Streaming Domains',
    'chris': 'Regional Blacklisted Domains',
    'warez': 'Warez Domains',
    'suspicious-tlds': 'Suspicious TLDs',
    'abuse-tlds': 'Abuse TLDs',
    'domains': 'Domain Blocklist',
    'lists': 'Security Lists',
    'malicious-ip': 'Malicious IPs',
    'bogons': 'Bogon IPs',
    'levels': 'Threat Intelligence IPs',
    'malware': 'Malware Hosting IPs',
    'spam-and-irrelevant-terms': 'Spam Keywords',
    'fake-onlydomains' : 'Likely Fake/Scam Domains',
    'whitelisted-domains': 'Whitelisted Domains',
    'disw-mcc-exclusion-master-list': 'Custom MCC Exclusion List'
  };
  const filenamePatterns = {
    'adlist': 'Ad Domains',
    'spam': 'Spam Domains',
    'privacy': 'Privacy Violating Domains',
    'abuse': 'Abuse Domains',
    'dga7': 'DGA Domains',
    'main': 'Main List',
    'hosting': 'Hosting IPs',
    'levels': 'Threat Level IPs'
  };
  const geoPatterns = {
    'brazil': 'Brazil',
    'china': 'China',
    'japan': 'Japan',
    'hong_kong' : 'Hong Kong',
    'india' : 'India',
    'philippines' : 'Philippines',
    'russia' : 'Russia'
  };
  let baseName = ownerPatterns[normalizedOwner] || capitalizeFirst(owner);
  let geoContext = '';
  Object.keys(geoPatterns).forEach(geo => {
    if (normalizedCategory.includes(geo) || normalizedFilename.includes(geo)) {
      geoContext = ` ${geoPatterns[geo]}`;
    }
  });
  let contentType = '';
  if (categoryPatterns[normalizedCategory]) {
    contentType = categoryPatterns[normalizedCategory];
  } else if (filenamePatterns[normalizedFilename.split('.')[0]]) {
    contentType = filenamePatterns[normalizedFilename.split('.')[0]];
  } else if (normalizedCategory.includes('ip') || normalizedFilename.includes('ip')) {
    if (normalizedCategory.includes('malicious') || normalizedFilename.includes('malicious')) {
      contentType = 'Malicious IPs';
    } else {
      contentType = 'IP Blocklist';
    }
  } else if (normalizedCategory.includes('domain') || normalizedFilename.includes('domain')) {
    if (normalizedCategory.includes('malicious') || normalizedFilename.includes('malicious')) {
      contentType = 'Malicious Domains';
    } else {
      contentType = 'Domain Blocklist';
    }
  } else if (normalizedCategory.includes('tld') || normalizedFilename.includes('tld')) {
    contentType = 'TLD Blocklist';
  } else {
    contentType = capitalizeFirst(category.replace(/[-_]/g, ' '));
  }
  if (normalizedFilename.includes('level-')) {
    const levelMatch = normalizedFilename.match(/level-(\d+)/);
    if (levelMatch) {
      contentType += ` (Level ${levelMatch[1]})`;
    }
  }
  if (normalizedFilename.includes('cidr')) {
    contentType += ' (CIDR)';
  }
  if (normalizedFilename.includes('ip4')) {
    contentType += ' (IPv4)';
  }
  const fullName = `${baseName}${geoContext} ${contentType}`;
  return fullName.trim();
}

/**
 * Capitalize first letter of a string
 */
function capitalizeFirst(str) {
  return str.charAt(0).toUpperCase() + str.slice(1);
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
    timings.blacklist_fetch = time_function(() => fetch_all_blacklists());
    validate_ip_matching();
    timings.pmax_fetch = time_function(() => {
      return fetch_pmax_placements();
    });
    const placements = fetch_pmax_placements();
    timings.analysis = time_function(() => analyze_placements(placements));
    timings.opr_fetch = time_function(() => fetch_open_page_rank_data(placements));
    timings.opr_apply = time_function(() => apply_open_page_rank_data(placements));
    timings.output = time_function(() => output_results(placements, timings, start_time));
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
  const ips = new Map();
  let total_loaded = 0;
  CONFIG.IP_BLOCKLIST.forEach((url, index) => {
    try {
      const listName = extractListName(url);
      console.log(`Loading IP list ${index + 1}/${CONFIG.IP_BLOCKLIST.length} from: ${listName}`);
      const response = fetchWithTimeout(url);
      if (response && response.getResponseCode() === 200) {
        let count = 0;
        response.getContentText().split('\n').forEach(line => {
          const trimmed = line.trim();
          if (trimmed && !trimmed.startsWith('#') && !trimmed.startsWith('//')) {
            let ip = trimmed;
            if (ip.includes(' ')) {
              ip = ip.split(' ')[0];
            }
            if (ip.includes('\t')) {
              ip = ip.split('\t')[0];
            }
            if (ip.match(/^\d+\.\d+\.\d+\.\d+(\/\d+)?$/)) {
              if (!ips.has(ip)) {
                ips.set(ip, [url]);
                count++;
              } else {
                const sources = ips.get(ip);
                if (!sources.includes(url)) {
                  sources.push(url);
                }
              }
            }
          }
        });
        console.log(`  Loaded ${count} IPs from ${listName}`);
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
 * Get all blacklist sources for a specific IP
 */
function get_ip_blacklist_sources(ip) {
  const sources = [];
  if (blacklisted_ips.has(ip)) {
    sources.push(...blacklisted_ips.get(ip));
  }
  const exact_match = `${ip}/32`;
  if (blacklisted_ips.has(exact_match)) {
    sources.push(...blacklisted_ips.get(exact_match));
  }
  for (const [blocked_cidr, cidr_sources] of blacklisted_ips) {
    if (blocked_cidr.includes('/') && is_ip_in_cidr(ip, blocked_cidr)) {
      sources.push(...cidr_sources);
    } else if (!blocked_cidr.includes('/') && blocked_cidr === ip) {
      sources.push(...cidr_sources);
    }
  }
  return [...new Set(sources)];
}

/**
 * Quick IP matching validation with source tracking
 */
function validate_ip_matching() {
  console.log('Validating IP matching with sample data...');
  const sample_tests = [
    '1.0.170.118',
    '1.10.16.5',
    '1.19.100.1',
    '8.8.8.8',
    '1.1.1.1'
  ];
  let matches = 0;
  sample_tests.forEach(ip => {
    const is_blocked = is_ip_blacklisted(ip);
    if (is_blocked) {
      matches++;
      const sources = get_ip_blacklist_sources(ip);
      const source_names = sources.map(source => extractListName(source));
      console.log(`IP ${ip}: BLOCKED (from ${source_names.join(', ')})`);
    } else {
      console.log(`IP ${ip}: ALLOWED`);
    }
  });
  console.log(`IP validation complete: ${matches}/${sample_tests.length} test IPs were blocked`);
  console.log(`Total IP entries in blacklist: ${blacklisted_ips.size}`);
}

/**
 * Check if IP is blacklisted - UPDATED FOR ARRAY SOURCES
 */
function is_ip_blacklisted(ip) {
  if (!ip || typeof ip !== 'string') {
    return false;
  }
  if (blacklisted_ips.has(ip)) {
    return true;
  }
  const exact_match = `${ip}/32`;
  if (blacklisted_ips.has(exact_match)) {
    return true;
  }
  for (const [blocked_cidr, sources] of blacklisted_ips) {
    if (blocked_cidr.includes('/')) {
      if (is_ip_in_cidr(ip, blocked_cidr)) {
        return true;
      }
    } else {
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
      return ip === cidr;
    }
    const [network, prefix_length] = cidr.split('/');
    const prefix = parseInt(prefix_length);
    if (isNaN(prefix) || prefix < 0 || prefix > 32) {
      return false;
    }
    const ip_parts = ip.split('.').map(Number);
    const network_parts = network.split('.').map(Number);
    if (ip_parts.length !== 4 || network_parts.length !== 4) {
      return false;
    }
    if (ip_parts.some(part => isNaN(part) || part < 0 || part > 255) ||
        network_parts.some(part => isNaN(part) || part < 0 || part > 255)) {
      return false;
    }
    const ip_int = (ip_parts[0] << 24) + (ip_parts[1] << 16) + (ip_parts[2] << 8) + ip_parts[3];
    const network_int = (network_parts[0] << 24) + (network_parts[1] << 16) + (network_parts[2] << 8) + network_parts[3];
    const mask = prefix === 0 ? 0 : (0xFFFFFFFF << (32 - prefix)) >>> 0;
    return (ip_int & mask) === (network_int & mask);
  } catch (error) {
    console.warn(`Error checking CIDR ${cidr} for IP ${ip}:`, error);
    return false;
  }
}

/**
 * Get all matching blacklist entries for a specific IP
 * Returns array of entries as they appear in blacklists (handles multiple formats)
 */
function get_matching_blacklist_entries(ip) {
  const matching_entries = [];
  
  // Check for exact IP match
  if (blacklisted_ips.has(ip)) {
    matching_entries.push(ip);
  }
  
  // Check for exact match with /32 notation
  const exact_match = `${ip}/32`;
  if (blacklisted_ips.has(exact_match)) {
    matching_entries.push(exact_match);
  }
  
  // Check all CIDR ranges and collect ALL matches
  for (const [blocked_cidr, sources] of blacklisted_ips) {
    if (blocked_cidr.includes('/')) {
      if (is_ip_in_cidr(ip, blocked_cidr)) {
        // Only add if not already in the list
        if (!matching_entries.includes(blocked_cidr)) {
          matching_entries.push(blocked_cidr);
        }
      }
    } else {
      if (blocked_cidr === ip) {
        // Only add if not already in the list
        if (!matching_entries.includes(blocked_cidr)) {
          matching_entries.push(blocked_cidr);
        }
      }
    }
  }
  
  // If no matches found, return the IP itself as fallback
  return matching_entries.length > 0 ? matching_entries : [ip];
}

/**
 * Get blacklist sources for a specific entry format
 */
function get_ip_blacklist_sources_for_entry(entry) {
  if (blacklisted_ips.has(entry)) {
    return blacklisted_ips.get(entry);
  }
  return [];
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
  if (tld.startsWith('.')) {
    const extracted_tld = tld.substring(1);
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
  const tlds = new Map();
  let total_loaded = 0;
  let filtered_count = 0;
  CONFIG.SUSPICIOUS_TLDS.forEach((url, index) => {
    try {
      const listName = extractListName(url);
      console.log(`Fetching suspicious TLD list ${index + 1}/${CONFIG.SUSPICIOUS_TLDS.length} from: ${listName}`);
      const response = fetchWithTimeout(url);
      if (response && response.getResponseCode() === 200) {
        let tlds_added = 0;
        let tlds_filtered = 0;
        response.getContentText()
          .split('\n')
          .forEach(line => {
            const extracted_tld = extractTld(line);
            if (extracted_tld) {
              if (CONFIG.FILTER_OUT_TLDS.includes(extracted_tld)) {
                tlds_filtered++;
                filtered_count++;
              } else {
                if (!tlds.has(extracted_tld)) {
                  tlds.set(extracted_tld, [url]);
                  tlds_added++;
                } else {
                  const sources = tlds.get(extracted_tld);
                  if (!sources.includes(url)) {
                    sources.push(url);
                  }
                }
              }
            }
          });
        console.log(`Loaded ${tlds_added} unique TLDs from ${listName} (filtered out ${tlds_filtered} legitimate TLDs)`);
        total_loaded += tlds_added;
      } else {
        throw new Error(`HTTP ${response ? response.getResponseCode() : 'unknown'}`);
      }
    } catch (error) {
      console.warn(`Failed to load TLD list ${index + 1}: ${url}`, error);
    }
  });
  if (tlds.size === 0) {
    console.warn('No TLD lists loaded successfully, adding fallback suspicious TLDs');
    const fallback_tlds = ['tk', 'ml', 'ga', 'cf', 'top', 'click', 'download', 'zip', 'review', 'country', 'stream'];
    fallback_tlds.forEach(tld => {
      if (!CONFIG.FILTER_OUT_TLDS.includes(tld)) {
        tlds.set(tld, ['fallback']);
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
  const domains = new Map();
  CONFIG.DOMAIN_BLOCKLIST.forEach((url, index) => {
    try {
      const listName = extractListName(url);
      console.log(`Fetching domain blocklist ${index + 1}/${CONFIG.DOMAIN_BLOCKLIST.length} from: ${listName}`);
      const response = fetchWithTimeout(url);
      if (response && response.getResponseCode() === 200) {
        let domains_added = 0;
        response.getContentText()
          .split('\n')
          .forEach(line => {
            const trimmed = line.trim().toLowerCase();
            if (trimmed && !trimmed.startsWith('#') && !trimmed.startsWith('//')) {
              let domain = trimmed;
              if (domain.includes(' ')) {
                const parts = domain.split(' ');
                domain = parts[parts.length - 1];
              }
              domain = domain.replace(/^\|\|/, '').replace(/\^.*$/, '');
              if (domain.includes('.') && !domain.includes('/') && domain.length > 3) {
                if (!domains.has(domain)) {
                  domains.set(domain, [url]);
                  domains_added++;
                } else {
                  const sources = domains.get(domain);
                  if (!sources.includes(url)) {
                    sources.push(url);
                  }
                }
              }
            }
          });
        console.log(`Loaded ${domains_added} unique domains from ${listName}`);
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
  spam_keywords = loadSpamKeywords();
  whitelisted_domains = loadWhitelistDomains();
  suspicious_tlds = loadSuspiciousTlds();
  blacklisted_domains = loadDomainBlocklists();
  blacklisted_ips = load_ip_blocklists();
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
    const dateRange = getDateRange(CONFIG.DATES_BACK);
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
    if (typeof AdsManagerApp !== 'undefined') {
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
            campaign_name: '',
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
      if (index < batches.length - 1) {
        Utilities.sleep(1000);
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
    if (check_auto_exclude_placement_type(placement)) return;
    if (!placement.target_url) return;
    const domain = extract_domain(placement.target_url);
    if (!domain) return;
    if (check_whitelisted_domain(domain, placement)) return;
    if (check_blacklisted_domain(domain, placement)) return;
    if (check_suspicious_tld(domain, placement)) return;
    if (check_spam_keywords_improved(domain, placement)) return;
  });
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
    let domain = url.replace(/^https?:\/\//, '');
    domain = domain.split('/')[0].split('?')[0].split('#')[0];
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
 * Check if domain is blacklisted - UPDATED FOR MULTIPLE SOURCES
 */
function check_blacklisted_domain(domain, placement) {
  if (blacklisted_domains.has(domain)) {
    const source_urls = blacklisted_domains.get(domain);
    const source_names = source_urls.map(url => extractListName(url));
    placement.action = 'EXCLUDE';
    placement.reason = `blacklisted domain; reported in ${source_names.join(', ')}`;
    placement.reference_list = '';
    return true;
  }
  const parts = domain.split('.');
  for (let i = 1; i < parts.length; i++) {
    const subdomain = parts.slice(i).join('.');
    if (blacklisted_domains.has(subdomain)) {
      const source_urls = blacklisted_domains.get(subdomain);
      const source_names = source_urls.map(url => extractListName(url));
      placement.action = 'EXCLUDE';
      placement.reason = `blacklisted domain (parent); reported in ${source_names.join(', ')}`;
      placement.reference_list = '';
      return true;
    }
  }
  return false;
}

/**
 * Check if TLD is suspicious - UPDATED FOR MULTIPLE SOURCES
 */
function check_suspicious_tld(domain, placement) {
  const tld = domain.split('.').pop();
  if (suspicious_tlds.has(tld)) {
    const source_urls = suspicious_tlds.get(tld);
    const source_names = source_urls.map(url => extractListName(url));
    placement.action = 'EXCLUDE';
    placement.reason = `suspicious TLD: ${tld}; reported in ${source_names.join(', ')}`;
    placement.reference_list = '';
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
  if (keywordLength <= CONFIG.SHORT_TERM_LENGTH) {
    const beforeChar = startIndex > 0 ? domain[startIndex - 1] : '';
    const afterChar = endIndex < domain.length ? domain[endIndex] : '';
    const atStart = startIndex === 0 || isWordBoundary(beforeChar);
    const atEnd = endIndex === domain.length || isWordBoundary(afterChar);
    return atStart && atEnd;
  }
  return true;
}

/**
 * Improved spam keyword checking with word boundary validation
 */
function check_spam_keywords_improved(domain, placement) {
  if (spam_keywords.length === 0) return false;
  const found_terms = [];
  const normalized_domain = domain.toLowerCase();
  spam_keywords.forEach(keyword => {
    const normalized_keyword = keyword.toLowerCase().trim();
    if (normalized_keyword.length === 0) return;
    let index = normalized_domain.indexOf(normalized_keyword);
    while (index !== -1) {
      if (isValidKeywordMatch(normalized_domain, normalized_keyword, index)) {
        found_terms.push(keyword);
        break;
      }
      index = normalized_domain.indexOf(normalized_keyword, index + 1);
    }
  });
  const unique_terms = [...new Set(found_terms)];
  if (unique_terms.length > 0) {
    const list_name = extractListName(CONFIG.SPAM_KEYWORDS);
    placement.action = 'EXCLUDE';
    placement.reason = `terms detected: ${unique_terms.join(', ')}; reported in ${list_name}`;
    placement.reference_list = '';
    return true;
  }
  return false;
}

/**
 * Simplified DNS resolver class
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
          dns_data.Answer
            .filter(record => record.type === 1)
            .forEach(record => {
              const ip = record.data;
              dns_info.ip_addresses.push(ip);
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
 * Perform DNS checks in batches - UPDATED TO SHOW ALL ORIGINAL BLACKLIST FORMATS
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
          const all_ip_details = [];
          
          dns_info.blacklisted_ips.forEach(blocked_ip => {
            // Get ALL matching blacklist entries for this IP
            const matching_entries = get_matching_blacklist_entries(blocked_ip);
            
            matching_entries.forEach(entry => {
              const sources = get_ip_blacklist_sources_for_entry(entry);
              const source_names = sources.map(source => extractListName(source));
              all_ip_details.push(`${entry} (${source_names.join(', ')})`);
            });
          });
          
          // Remove duplicates and format output
          const unique_details = [...new Set(all_ip_details)];
          const ip_details = unique_details.join('\n');
          placement.reason = `blacklisted IP:\n${ip_details}`;
          placement.reference_list = '';
        }
      } catch (error) {
        console.warn(`DNS lookup failed for ${domain}:`, error);
      }
    });
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
  const est_offset = -5;
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
    let analysis_sheet = spreadsheet.getSheetByName('web-exclusions');
    if (!analysis_sheet) {
      analysis_sheet = spreadsheet.insertSheet('web-exclusions');
    }
    let raw_sheet = spreadsheet.getSheetByName('gaql_output');
    if (!raw_sheet) {
      raw_sheet = spreadsheet.insertSheet('gaql_output');
      raw_sheet.hideSheet();
    }
    let reference_sheet = spreadsheet.getSheetByName('reference-lists');
    if (!reference_sheet) {
      reference_sheet = spreadsheet.insertSheet('reference-lists');
    }
    output_raw_data(raw_sheet, placements);
    output_analysis_data(analysis_sheet, placements, timings, start_time);
    output_reference_lists(reference_sheet);
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
 * Output reference lists data to new sheet
 */
function output_reference_lists(sheet) {
  sheet.clear();
  const headers = ['Repository Name', 'Type', 'Size', 'URL'];
  sheet.getRange(1, 1, 1, headers.length).setValues([headers]);
  const reference_data = [];
  reference_data.push([
    extractListName(CONFIG.SPAM_KEYWORDS),
    'Keywords',
    spam_keywords.length,
    createHyperlink(CONFIG.SPAM_KEYWORDS, extractListName(CONFIG.SPAM_KEYWORDS))
  ]);
  reference_data.push([
    extractListName(CONFIG.WHITELIST_DOMAINS),
    'Whitelist Domains',
    whitelisted_domains.size,
    createHyperlink(CONFIG.WHITELIST_DOMAINS, extractListName(CONFIG.WHITELIST_DOMAINS))
  ]);
  const processed_domain_urls = new Set();
  for (const [domain, source_urls] of blacklisted_domains) {
    source_urls.forEach(url => {
      if (!processed_domain_urls.has(url)) {
        processed_domain_urls.add(url);
        const domains_from_this_source = Array.from(blacklisted_domains.entries())
          .filter(([d, urls]) => urls.includes(url)).length;
        reference_data.push([
          extractListName(url),
          'Domain Blocklist',
          domains_from_this_source,
          createHyperlink(url, extractListName(url))
        ]);
      }
    });
  }
  const processed_tld_urls = new Set();
  for (const [tld, source_urls] of suspicious_tlds) {
    source_urls.forEach(url => {
      if (!processed_tld_urls.has(url)) {
        processed_tld_urls.add(url);
        const tlds_from_this_source = Array.from(suspicious_tlds.entries())
          .filter(([t, urls]) => urls.includes(url)).length;
        reference_data.push([
          extractListName(url),
          'TLD Blocklist',
          tlds_from_this_source,
          createHyperlink(url, extractListName(url))
        ]);
      }
    });
  }
  const processed_ip_urls = new Set();
  for (const [ip, source_urls] of blacklisted_ips) {
    source_urls.forEach(url => {
      if (!processed_ip_urls.has(url)) {
        processed_ip_urls.add(url);
        const ips_from_this_source = Array.from(blacklisted_ips.entries())
          .filter(([i, urls]) => urls.includes(url)).length;
        reference_data.push([
          extractListName(url),
          'IP Blocklist',
          ips_from_this_source,
          createHyperlink(url, extractListName(url))
        ]);
      }
    });
  }
  if (reference_data.length > 0) {
    sheet.getRange(2, 1, reference_data.length, headers.length).setValues(reference_data);
  }
  sheet.getRange(1, 1, 1, headers.length).setFontWeight('bold');
  sheet.getRange(1, 1, 1, headers.length).setBackground('#d9d9d9');
  sheet.autoResizeColumns(1, headers.length);
  console.log(`Output ${reference_data.length} reference lists to reference-lists sheet`);
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
  const unique_customers = [...new Set(placements.map(p => `${p.customer_name} - ${p.customer_id}`))];
  const customer_display = unique_customers.length > 0 ? unique_customers.join(', ') : 'No accounts found';
  const summary_data = [
    [`Account: ${customer_display}`],
    [`Script Last Refresh: ${current_datetime}`],
    [`Script Total Runtime: ${(total_time / 1000).toFixed(2)} seconds`],
    [`Date Range: ${dateRange.startDate} to ${dateRange.endDate}`],
    [`Total PMAX Placements: ${placements.length} | Recommended Exclusions: ${excluded_count} | Whitelisted: ${keep_count}`],
    [`Blacklist Stats: ${spam_keywords.length} keywords, ${blacklisted_domains.size} domains, ${suspicious_tlds.size} TLDs, ${blacklisted_ips.size} IPs`],
    [`Open Page Rank: ${domain_page_ranks.size} domains analyzed | API Status: ${CONFIG.OPR_ENABLED ? 'Enabled' : 'Disabled'}`]
  ];
  summary_data.forEach((row, index) => {
    sheet.getRange(index + 1, 1, 1, 1).setValue(row[0]);
  });
  sheet.getRange(1, 1, 1, 1).setFontWeight('bold');
  sheet.getRange(2, 1, 4, 1).setFontStyle('italic');
  const header_row = 9;
  const headers = [
    'Campaign ID',
    'Placement Type',
    'Placement',
    'Impr.',
    'Display Name',
    'Action',
    'Reason',
    'Page Rank',
    'Domain Rank'
  ];
  sheet.getRange(header_row, 1, 1, headers.length).setValues([headers]);
  const header_range = sheet.getRange(header_row, 1, 1, headers.length);
  header_range.setFontWeight('bold');
  header_range.setBackground('#d9d9d9');
  header_range.setWrap(true);
  if (placements.length > 0) {
    const data = placements.map(placement => [
      placement.campaign_id || '',
      placement.placement_type || '',
      placement.target_url || '',
      placement.impressions || 0,
      placement.display_name || '',
      placement.action || 'NEUTRAL',
      placement.reason || '',
      placement.page_rank || '',
      placement.domain_rank || ''
    ]);
    sheet.getRange(header_row + 1, 1, data.length, headers.length).setValues(data);
    const action_range = sheet.getRange(header_row + 1, 6, data.length, 1);
    const exclude_rule = SpreadsheetApp.newConditionalFormatRule()
      .whenTextEqualTo('EXCLUDE')
      .setBackground('#ffcccc')
      .setRanges([action_range])
      .build();
    const keep_rule = SpreadsheetApp.newConditionalFormatRule()
      .whenTextEqualTo('KEEP')
      .setBackground('#ccffcc')
      .setRanges([action_range])
      .build();
    const rules = sheet.getConditionalFormatRules();
    rules.push(exclude_rule);
    rules.push(keep_rule);
    sheet.setConditionalFormatRules(rules);
    const reason_range = sheet.getRange(header_row + 1, 7, data.length, 1);
    reason_range.setWrap(true);
    sheet.setColumnWidth(7, 350);
    sheet.setColumnWidth(2, 120);
    sheet.setColumnWidth(4, 80);
    sheet.setColumnWidth(8, 80);
    sheet.setColumnWidth(9, 100);
  }
  for (let i = 1; i <= headers.length; i++) {
    if (![2, 4, 7, 8, 9].includes(i)) {
      sheet.autoResizeColumn(i);
    }
  }
  console.log(`Output ${placements.length} rows to web-exclusions sheet`);
}

/**
 * Utility functions
 */
function time_function(func) {
  const start = new Date();
  const result = func();
  return new Date() - start;
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
