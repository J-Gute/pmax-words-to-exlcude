/**
 * PMAX YouTube Placement Analysis Script
 * Fetches blacklists, analyzes PMAX YouTube placements, and flags suspicious channels/videos
 */

const CACHE_CONFIG = {
  CACHE_DURATION_WEEKS: 4,
  CACHE_DURATION_MS: 4 * 7 * 24 * 60 * 60 * 1000,
  CACHE_KEY_PREFIX: 'yt_channel_',
  CACHE_METADATA_KEY: 'yt_cache_metadata',
  MAX_CACHE_ENTRIES: 2000, 
  CLEANUP_INTERVAL_DAYS: 7
};

// Enhanced channel cache with persistent storage
class YouTubeChannelCache {
  constructor() {
    this.properties = PropertiesService.getScriptProperties();
    this.memoryCache = new Map(); // In-memory cache for current session
    this.cacheStats = {
      hits: 0,
      misses: 0,
      fetches: 0,
      stores: 0
    };
  }

  // Generate cache key for video ID
  generateCacheKey(videoId) {
    return `${CACHE_CONFIG.CACHE_KEY_PREFIX}${videoId}`;
  }

  // Get channel info from cache (memory first, then persistent)
  get(videoId) {
    if (!videoId) return null;

    // Check memory cache first (fastest)
    if (this.memoryCache.has(videoId)) {
      this.cacheStats.hits++;
      return this.memoryCache.get(videoId);
    }

    // Check persistent cache
    try {
      const cacheKey = this.generateCacheKey(videoId);
      const cachedData = this.properties.getProperty(cacheKey);
      
      if (cachedData) {
        const parsed = JSON.parse(cachedData);
        const now = Date.now();
        
        // Check if cache entry is still valid
        if (now - parsed.timestamp < CACHE_CONFIG.CACHE_DURATION_MS) {
          // Store in memory cache for faster access
          this.memoryCache.set(videoId, parsed.data);
          this.cacheStats.hits++;
          return parsed.data;
        } else {
          // Cache expired, remove it
          this.properties.deleteProperty(cacheKey);
        }
      }
    } catch (error) {
      console.warn(`Cache read error for ${videoId}:`, error);
    }

    this.cacheStats.misses++;
    return null;
  }

  // Store channel info in cache (both memory and persistent)
  set(videoId, channelInfo) {
    if (!videoId || !channelInfo) return;

    try {
      // Store in memory cache
      this.memoryCache.set(videoId, channelInfo);

      // Store in persistent cache with timestamp
      const cacheKey = this.generateCacheKey(videoId);
      const cacheEntry = {
        data: channelInfo,
        timestamp: Date.now(),
        videoId: videoId
      };

      this.properties.setProperty(cacheKey, JSON.stringify(cacheEntry));
      this.cacheStats.stores++;

      // Update cache metadata
      this.updateCacheMetadata(videoId);

    } catch (error) {
      console.warn(`Cache write error for ${videoId}:`, error);
    }
  }

  // Update cache metadata for cleanup purposes
  updateCacheMetadata(videoId) {
    try {
      const metadataStr = this.properties.getProperty(CACHE_CONFIG.CACHE_METADATA_KEY);
      let metadata = metadataStr ? JSON.parse(metadataStr) : { entries: [], lastCleanup: 0 };

      // Add new entry
      metadata.entries.push({
        videoId: videoId,
        timestamp: Date.now()
      });

      // Keep only recent entries to prevent metadata from growing too large
      const cutoff = Date.now() - CACHE_CONFIG.CACHE_DURATION_MS;
      metadata.entries = metadata.entries.filter(entry => entry.timestamp > cutoff);

      // Limit total entries
      if (metadata.entries.length > CACHE_CONFIG.MAX_CACHE_ENTRIES) {
        metadata.entries = metadata.entries.slice(-CACHE_CONFIG.MAX_CACHE_ENTRIES);
      }

      this.properties.setProperty(CACHE_CONFIG.CACHE_METADATA_KEY, JSON.stringify(metadata));
    } catch (error) {
      console.warn('Cache metadata update error:', error);
    }
  }

  // Clean up expired cache entries
  cleanup() {
    try {
      console.log('Starting cache cleanup...');
      const metadataStr = this.properties.getProperty(CACHE_CONFIG.CACHE_METADATA_KEY);
      
      if (!metadataStr) {
        console.log('No cache metadata found, skipping cleanup');
        return;
      }

      const metadata = JSON.parse(metadataStr);
      const now = Date.now();
      const cutoff = now - CACHE_CONFIG.CACHE_DURATION_MS;
      let deletedCount = 0;

      // Check if cleanup is needed
      const cleanupInterval = CACHE_CONFIG.CLEANUP_INTERVAL_DAYS * 24 * 60 * 60 * 1000;
      if (metadata.lastCleanup && (now - metadata.lastCleanup) < cleanupInterval) {
        console.log('Cache cleanup not needed yet');
        return;
      }

      // Clean up expired entries
      for (const entry of metadata.entries) {
        if (entry.timestamp < cutoff) {
          const cacheKey = this.generateCacheKey(entry.videoId);
          this.properties.deleteProperty(cacheKey);
          deletedCount++;
        }
      }

      // Update metadata
      metadata.entries = metadata.entries.filter(entry => entry.timestamp >= cutoff);
      metadata.lastCleanup = now;
      this.properties.setProperty(CACHE_CONFIG.CACHE_METADATA_KEY, JSON.stringify(metadata));

      console.log(`Cache cleanup complete: ${deletedCount} expired entries removed`);
    } catch (error) {
      console.warn('Cache cleanup error:', error);
    }
  }

  // Get cache statistics
  getStats() {
    const hitRate = this.cacheStats.hits + this.cacheStats.misses > 0 
      ? (this.cacheStats.hits / (this.cacheStats.hits + this.cacheStats.misses) * 100).toFixed(1)
      : 0;

    return {
      ...this.cacheStats,
      hitRate: `${hitRate}%`,
      memorySize: this.memoryCache.size
    };
  }

  // Clear all cache data (for testing/debugging)
  clear() {
    try {
      // Clear memory cache
      this.memoryCache.clear();

      // Clear persistent cache
      const metadataStr = this.properties.getProperty(CACHE_CONFIG.CACHE_METADATA_KEY);
      if (metadataStr) {
        const metadata = JSON.parse(metadataStr);
        for (const entry of metadata.entries) {
          const cacheKey = this.generateCacheKey(entry.videoId);
          this.properties.deleteProperty(cacheKey);
        }
      }

      // Clear metadata
      this.properties.deleteProperty(CACHE_CONFIG.CACHE_METADATA_KEY);
      
      console.log('Cache cleared successfully');
    } catch (error) {
      console.warn('Cache clear error:', error);
    }
  }
}

// Global cache instance
let youtubeChannelCache = new YouTubeChannelCache();

const YT_CONFIG = {
  CHANNEL_BLACKLISTS: [
    'https://raw.githubusercontent.com/J-Gute/pmax-placement-evaluator/refs/heads/main/yt-kids-channels',
    'https://raw.githubusercontent.com/J-Gute/pmax-placement-evaluator/refs/heads/main/yt-spam-irrelevant-channels'
  ],
  MCC_VIDEO_EXCLUSION: 'https://raw.githubusercontent.com/J-Gute/pmax-placement-evaluator/refs/heads/main/yt-mcc-vid-exclusions',
  NEGATIVE_TERMS_LISTS: [
    'https://raw.githubusercontent.com/J-Gute/pmax-placement-evaluator/refs/heads/main/spam-and-irrelevant-terms',
    'https://raw.githubusercontent.com/J-Gute/pmax-placement-evaluator/refs/heads/main/yt-negative-term-phrases/jp-negatives',
    'https://raw.githubusercontent.com/J-Gute/pmax-placement-evaluator/refs/heads/main/yt-negative-term-phrases/kr-negatives',
    'https://raw.githubusercontent.com/J-Gute/pmax-placement-evaluator/refs/heads/main/yt-negative-term-phrases/ru-negatives',
    'https://raw.githubusercontent.com/J-Gute/pmax-placement-evaluator/refs/heads/main/yt-negative-term-phrases/th-negatives'
  ],
  SHEET_URL: 'URL here',
  DATES_BACK: 15,
  MIN_IMPRESSIONS: 2,
  BATCH_SIZE: 50,
  MAX_RETRIES: 3,
  REQUEST_DELAY: 500,
  MIN_NGRAM: 1,
  MAX_NGRAM: 3,
  MIN_TERM_LENGTH: 3,
  MIN_PHRASE_LENGTH: 4,
  EXACT_MATCH_REQUIRED: true,
  ENABLE_DETAILED_LOGGING: true,
  YOUTUBE_FETCH_DELAY: 1000, // Delay between YouTube page fetches
  MAX_YOUTUBE_FETCHES: 100   // Limit to avoid timeouts
};

let yt_channel_blacklist = new Map();
let mcc_video_exclusions = new Set();
let negative_terms = new Map();
let youtube_fetch_count = 0;

function extractYtListName(url) {
  try {
    const cleanUrl = String(url).trim();
    if (!cleanUrl.includes('raw.githubusercontent.com') && !cleanUrl.includes('jsdelivr.net')) {
      return cleanUrl;
    }
    if (cleanUrl.includes('jsdelivr.net')) {
      const jsdelivr_match = cleanUrl.match(/cdn\.jsdelivr\.net\/gh\/([^\/]+)\/([^@\/]+)@?[^\/]*\/(.+)/);
      if (jsdelivr_match) {
        const [, owner, repo, path] = jsdelivr_match;
        const category = path.split('/')[0] || 'unknown';
        const filename = path.split('/').pop() || 'unknown';
        return generateYtDynamicName(owner, repo, category, filename, 'jsdelivr');
      }
    }
    const urlParts = cleanUrl.split('/');
    if (urlParts.length < 6) return cleanUrl;
    const repo_owner = urlParts[3] || 'unknown';
    const repo_name = urlParts[4] || 'unknown';
    let category, filename;
    if (cleanUrl.includes('/refs/heads/main/') || cleanUrl.includes('/refs/heads/master/')) {
      const pathStart = cleanUrl.includes('/refs/heads/main/') ?
        cleanUrl.indexOf('/refs/heads/main/') + '/refs/heads/main/'.length :
        cleanUrl.indexOf('/refs/heads/master/') + '/refs/heads/master/'.length;
      const remainingPath = cleanUrl.substring(pathStart);
      const pathParts = remainingPath.split('/');
      category = pathParts[0] || 'unknown';
      filename = pathParts[pathParts.length - 1] || 'unknown';
    } else if (cleanUrl.includes('/master/') || cleanUrl.includes('/main/')) {
      const branchIndex = cleanUrl.includes('/master/') ? 
        cleanUrl.indexOf('/master/') + '/master/'.length :
        cleanUrl.indexOf('/main/') + '/main/'.length;
      const remainingPath = cleanUrl.substring(branchIndex);
      const pathParts = remainingPath.split('/');
      category = pathParts[0] || 'unknown';
      filename = pathParts[pathParts.length - 1] || 'unknown';
    } else {
      category = urlParts[urlParts.length - 2] || 'unknown';
      filename = urlParts[urlParts.length - 1] || 'unknown';
    }
    return generateYtDynamicName(repo_owner, repo_name, category, filename, 'github');
  } catch (error) {
    console.warn('Error extracting YT list name from URL:', url, error);
    return 'Unknown YouTube Source';
  }
}

function generateYtDynamicName(owner, repo, category, filename, platform) {
  const normalizedOwner = owner.toLowerCase();
  const normalizedRepo = repo.toLowerCase();
  const normalizedCategory = category.toLowerCase();
  const normalizedFilename = filename.toLowerCase();
  
  const ownerPatterns = {
    'j-gute': 'di sw'
  };
  
  const categoryPatterns = {
    'streaming': 'YouTube Streaming',
    'yt-channels': 'YouTube Channels',
    'yt-terms': 'Negative Terms & Phrases',
    'yt-negative': 'YouTube Negative Content',
    'yt-negative-term-phrases': 'Regional Negative Terms',
    'mcc-master': 'MCC Master List',
    'adult-themed': 'Adult Content'
  };
  
  const filenamePatterns = {
    'channel-blacklist': 'Channel Blacklist',
    'video-exclusion': 'Video Exclusions',
    'negative-terms': '"Spam" and/or Irrelevant Terms',
    'negative-phrases': 'Negative Phrases',
    'spam-channels': '"Spam" and/or Irrelevant Channels',
    'spam-terms': 'Spam Terms',
    // Regional negative terms
    'jp-negatives': 'Japanese Negative Terms',
    'kr-negatives': 'Korean Negative Terms',
    'ru-negatives': 'Russian Negative Terms',
    'th-negatives': 'Thai Negative Terms',
    'cn-negatives': 'Chinese (Simplified) Negative Terms'
  };
  
  let baseName = ownerPatterns[normalizedOwner] || capitalizeFirst(owner);
  let contentType = '';
  
  // Check for specific filename patterns first (for regional files)
  if (filenamePatterns[normalizedFilename.split('.')[0]]) {
    contentType = filenamePatterns[normalizedFilename.split('.')[0]];
  } else if (categoryPatterns[normalizedCategory]) {
    contentType = categoryPatterns[normalizedCategory];
  } else if (normalizedFilename.includes('channel')) {
    contentType = 'YouTube Channels';
  } else if (normalizedFilename.includes('video')) {
    contentType = 'YouTube Videos';
  } else if (normalizedFilename.includes('term') || normalizedFilename.includes('phrase')) {
    contentType = 'YouTube Terms';
  } else {
    contentType = capitalizeFirst(category.replace(/[-_]/g, ' '));
  }
  
  return `${baseName} ${contentType}`.trim();
}

function capitalizeFirst(str) {
  return str.charAt(0).toUpperCase() + str.slice(1);
}

function fetchYtWithTimeout(url, timeoutMs = 30000) {
  let lastError;
  for (let attempt = 1; attempt <= YT_CONFIG.MAX_RETRIES; attempt++) {
    try {
      const response = UrlFetchApp.fetch(url, {
        method: 'GET',
        muteHttpExceptions: true,
        headers: {
          'User-Agent': 'Mozilla/5.0 (compatible; GoogleAdsBot/1.0)'
        }
      });
      if (response.getResponseCode() === 200) {
        return response;
      } else {
        throw new Error(`HTTP ${response.getResponseCode()}`);
      }
    } catch (error) {
      lastError = error;
      if (attempt < YT_CONFIG.MAX_RETRIES) {
        console.warn(`Attempt ${attempt} failed for ${url}, retrying...`);
        Utilities.sleep(YT_CONFIG.REQUEST_DELAY * attempt);
      }
    }
  }
  throw lastError;
}

function extractVideoId(url) {
  try {
    if (!url) return null;
    if (url.includes('youtube.com/watch?v=')) {
      return url.match(/v=([^&]+)/)?.[1];
    }
    if (url.includes('youtu.be/')) {
      return url.match(/youtu\.be\/([^?]+)/)?.[1];
    }
    if (url.includes('youtube.com/video/')) {
      return url.match(/video\/([^\/\?&]+)/)?.[1];
    }
    if (url.match(/^[a-zA-Z0-9_-]{11}$/)) {
      return url;
    }
    return null;
  } catch (error) {
    console.warn('Error extracting video ID from:', url, error);
    return null;
  }
}

// ENHANCED: Fetch YouTube video page and extract channel information with 4-week caching
function fetchYouTubeChannelInfo(videoId) {
  if (!videoId || youtube_fetch_count >= YT_CONFIG.MAX_YOUTUBE_FETCHES) {
    return { channel_id: null, channel_handle: null, channel_name: null };
  }
  
  // Check cache first (4-week persistent cache)
  const cachedInfo = youtubeChannelCache.get(videoId);
  if (cachedInfo) {
    if (YT_CONFIG.ENABLE_DETAILED_LOGGING && youtube_fetch_count <= 5) {
      console.log(`Cache HIT for video ${videoId}: ${cachedInfo.channel_id || cachedInfo.channel_handle || 'no channel info'}`);
    }
    return cachedInfo;
  }
  
  try {
    youtube_fetch_count++;
    youtubeChannelCache.cacheStats.fetches++;
    
    const videoUrl = `https://www.youtube.com/watch?v=${videoId}`;
    
    if (YT_CONFIG.ENABLE_DETAILED_LOGGING && youtube_fetch_count <= 5) {
      console.log(`Fetching YouTube page ${youtube_fetch_count}: ${videoUrl}`);
    }
    
    const response = UrlFetchApp.fetch(videoUrl, {
      method: 'GET',
      muteHttpExceptions: true,
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
      }
    });
    
    if (response.getResponseCode() !== 200) {
      throw new Error(`HTTP ${response.getResponseCode()}`);
    }
    
    const html = response.getContentText();
    const channelInfo = extractChannelFromHtml(html);
    
    // Cache the result for 4 weeks
    youtubeChannelCache.set(videoId, channelInfo);
    
    if (YT_CONFIG.ENABLE_DETAILED_LOGGING && youtube_fetch_count <= 5) {
      console.log(`Extracted and cached: ${channelInfo.channel_id || channelInfo.channel_handle || 'no channel info'}`);
    }
    
    // Add delay to avoid rate limiting
    if (youtube_fetch_count < YT_CONFIG.MAX_YOUTUBE_FETCHES) {
      Utilities.sleep(YT_CONFIG.YOUTUBE_FETCH_DELAY);
    }
    
    return channelInfo;
    
  } catch (error) {
    console.warn(`Failed to fetch YouTube page for video ${videoId}:`, error);
    const emptyInfo = { channel_id: null, channel_handle: null, channel_name: null };
    
    // Cache empty result to avoid retrying
    youtubeChannelCache.set(videoId, emptyInfo);
    
    return emptyInfo;
  }
}

// Extract channel information from YouTube HTML
function extractChannelFromHtml(html) {
  const channelInfo = {
    channel_id: null,
    channel_handle: null,
    channel_name: null
  };
  
  try {
    // Method 1: Look for channel ID in various JSON data
    let match = html.match(/"channelId":"([^"]+)"/);
    if (match) {
      channelInfo.channel_id = match[1];
    }
    
    // Method 2: Look for channel ID in ownerChannelName
    if (!channelInfo.channel_id) {
      match = html.match(/"ownerChannelName":"[^"]*","externalChannelId":"([^"]+)"/);
      if (match) {
        channelInfo.channel_id = match[1];
      }
    }
    
    // Method 3: Look for UC pattern in various contexts
    if (!channelInfo.channel_id) {
      match = html.match(/(UC[a-zA-Z0-9_-]{22})/);
      if (match) {
        channelInfo.channel_id = match[1];
      }
    }
    
    // Method 4: Look for channel handle (@handle)
    match = html.match(/"canonicalChannelUrl":"[^"]*\/@([^"\/]+)"/);
    if (match) {
      channelInfo.channel_handle = match[1];
    }
    
    // Method 5: Look for channel handle in different format
    if (!channelInfo.channel_handle) {
      match = html.match(/"webCommandMetadata":{"url":"[^"]*\/@([^"\/]+)"/);
      if (match) {
        channelInfo.channel_handle = match[1];
      }
    }
    
    // Method 6: Look for channel name
    match = html.match(/"ownerChannelName":"([^"]+)"/);
    if (match) {
      channelInfo.channel_name = match[1];
    }
    
    // Method 7: Look for channel name in author
    if (!channelInfo.channel_name) {
      match = html.match(/"author":"([^"]+)"/);
      if (match) {
        channelInfo.channel_name = match[1];
      }
    }
    
    return channelInfo;
    
  } catch (error) {
    console.warn('Error extracting channel info from HTML:', error);
    return channelInfo;
  }
}

// Enhanced channel extraction with YouTube page lookup and 4-week caching
function extractChannelIdentifiers(placement) {
  const identifiers = {
    channel_id: null,
    channel_handle: null,
    video_id: null
  };
  
  try {
    // Extract video ID first
    if (placement.target_url) {
      identifiers.video_id = extractVideoId(placement.target_url);
    }
    
    // Try to extract channel info from placement data first (fast)
    const sources = [placement.target_url, placement.placement, placement.display_name, placement.resource_name].filter(Boolean);
    
    for (const source of sources) {
      const value = String(source);
      
      // Channel ID patterns
      if (!identifiers.channel_id) {
        const channelMatch = value.match(/youtube\.com\/channel\/([a-zA-Z0-9_-]+)/);
        if (channelMatch) {
          identifiers.channel_id = channelMatch[1];
        }
        
        const idMatch = value.match(/(UC[a-zA-Z0-9_-]{22})/);
        if (idMatch) {
          identifiers.channel_id = idMatch[0];
        }
      }
      
      // Channel handle patterns
      if (!identifiers.channel_handle) {
        const handleMatch = value.match(/@([a-zA-Z0-9_.-]+)/);
        if (handleMatch) {
          identifiers.channel_handle = handleMatch[1];
        }
        
        const cMatch = value.match(/youtube\.com\/c\/([a-zA-Z0-9_.-]+)/);
        if (cMatch) {
          identifiers.channel_handle = cMatch[1];
        }
        
        const userMatch = value.match(/youtube\.com\/user\/([a-zA-Z0-9_.-]+)/);
        if (userMatch) {
          identifiers.channel_handle = userMatch[1];
        }
      }
    }
    
    // If we didn't find channel info in placement data, fetch from YouTube page (with 4-week caching)
    if (!identifiers.channel_id && !identifiers.channel_handle && identifiers.video_id) {
      const youtubeInfo = fetchYouTubeChannelInfo(identifiers.video_id);
      identifiers.channel_id = youtubeInfo.channel_id;
      identifiers.channel_handle = youtubeInfo.channel_handle;
      // Store channel name for reference
      if (youtubeInfo.channel_name) {
        identifiers.channel_name = youtubeInfo.channel_name;
      }
    }
    
    return identifiers;
    
  } catch (error) {
    console.warn('Error extracting channel identifiers:', error);
    return identifiers;
  }
}

function loadYtChannelBlacklists() {
  console.log('Fetching YouTube channel blacklists...');
  const channels = new Map();
  let total_loaded = 0;
  YT_CONFIG.CHANNEL_BLACKLISTS.forEach((url, index) => {
    try {
      const listName = extractYtListName(url);
      console.log(`Loading channel list ${index + 1}/${YT_CONFIG.CHANNEL_BLACKLISTS.length} from: ${listName}`);
      const response = fetchYtWithTimeout(url);
      if (response && response.getResponseCode() === 200) {
        let count = 0;
        response.getContentText().split('\n').forEach(line => {
          const trimmed = line.trim();
          if (trimmed && !trimmed.startsWith('#') && !trimmed.startsWith('//')) {
            let channel_identifier = trimmed;
            if (channel_identifier.includes('youtube.com/channel/')) {
              const extracted_id = channel_identifier.match(/channel\/([^\/\?&]+)/)?.[1];
              if (extracted_id && extracted_id !== '') {
                channel_identifier = extracted_id;
              }
            } else if (channel_identifier.includes('youtube.com/@')) {
              const extracted_handle = channel_identifier.match(/@([^\/\?&]+)/)?.[1];
              if (extracted_handle && extracted_handle !== '') {
                channel_identifier = `@${extracted_handle}`;
              }
            }
            if (channel_identifier.length > 3 && channel_identifier !== 'https://www.youtube.com/channel/') {
              if (!channels.has(channel_identifier)) {
                channels.set(channel_identifier, [url]);
                count++;
              } else {
                const sources = channels.get(channel_identifier);
                if (!sources.includes(url)) {
                  sources.push(url);
                }
              }
            }
          }
        });
        console.log(`  Loaded ${count} channels from ${listName}`);
        total_loaded += count;
      } else {
        throw new Error(`HTTP ${response ? response.getResponseCode() : 'unknown'}`);
      }
    } catch (error) {
      console.warn(`Failed to load channel list from ${url}:`, error);
    }
  });
  console.log(`Total unique blacklisted channels loaded: ${channels.size} (${total_loaded} total entries processed)`);
  return channels;
}

function loadMccVideoExclusions() {
  console.log('Fetching MCC video exclusion list...');
  const videos = new Set();
  try {
    const listName = extractYtListName(YT_CONFIG.MCC_VIDEO_EXCLUSION);
    console.log(`Loading MCC video exclusions from: ${listName}`);
    const response = fetchYtWithTimeout(YT_CONFIG.MCC_VIDEO_EXCLUSION);
    if (response && response.getResponseCode() === 200) {
      let count = 0;
      response.getContentText().split('\n').forEach(line => {
        const trimmed = line.trim();
        if (trimmed && !trimmed.startsWith('#') && !trimmed.startsWith('//')) {
          let video_identifier = trimmed;
          const video_id = extractVideoId(video_identifier);
          if (video_id) {
            videos.add(video_identifier);
            videos.add(video_id);
            videos.add(`https://www.youtube.com/watch?v=${video_id}`);
            videos.add(`https://youtu.be/${video_id}`);
            videos.add(`youtube.com/video/${video_id}`);
            count++;
          }
        }
      });
      console.log(`  Loaded ${count} video exclusions from ${listName}`);
    } else {
      throw new Error(`HTTP ${response ? response.getResponseCode() : 'unknown'}`);
    }
  } catch (error) {
    console.warn(`Failed to load MCC video exclusions from ${YT_CONFIG.MCC_VIDEO_EXCLUSION}:`, error);
  }
  console.log(`Total MCC video exclusions loaded: ${videos.size}`);
  return videos;
}

function loadNegativeTerms() {
  console.log('Fetching negative terms and phrases...');
  const terms = new Map();
  let total_loaded = 0;
  YT_CONFIG.NEGATIVE_TERMS_LISTS.forEach((url, index) => {
    try {
      const listName = extractYtListName(url);
      console.log(`Loading terms list ${index + 1}/${YT_CONFIG.NEGATIVE_TERMS_LISTS.length} from: ${listName}`);
      const response = fetchYtWithTimeout(url);
      if (response && response.getResponseCode() === 200) {
        let count = 0;
        response.getContentText().split('\n').forEach(line => {
          const trimmed = line.trim().toLowerCase();
          if (trimmed && !trimmed.startsWith('#') && !trimmed.startsWith('//') && trimmed.length >= YT_CONFIG.MIN_TERM_LENGTH) {
            if (!terms.has(trimmed)) {
              terms.set(trimmed, [url]);
              count++;
            } else {
              const sources = terms.get(trimmed);
              if (!sources.includes(url)) {
                sources.push(url);
              }
            }
          }
        });
        console.log(`  Loaded ${count} terms from ${listName}`);
        total_loaded += count;
      } else {
        throw new Error(`HTTP ${response ? response.getResponseCode() : 'unknown'}`);
      }
    } catch (error) {
      console.warn(`Failed to load terms list from ${url}:`, error);
    }
  });
  console.log(`Total unique negative terms loaded: ${terms.size} (${total_loaded} total entries processed)`);
  return terms;
}

function fetchAllYtBlacklists() {
  console.log('Fetching YouTube blacklists...');
  
  // Perform cache cleanup at the start
  youtubeChannelCache.cleanup();
  
  yt_channel_blacklist = loadYtChannelBlacklists();
  mcc_video_exclusions = loadMccVideoExclusions();
  negative_terms = loadNegativeTerms();
  console.log('\n=== YOUTUBE BLACKLIST SUMMARY ===');
  console.log(`Channel blacklist: ${yt_channel_blacklist.size} unique entries`);
  console.log(`MCC video exclusions: ${mcc_video_exclusions.size} unique entries`);
  console.log(`Negative terms: ${negative_terms.size} unique entries`);
  console.log('=================================\n');
}

function getYtDateRange(daysBack) {
  const endDate = new Date();
  const startDate = new Date();
  startDate.setDate(startDate.getDate() - daysBack);
  return {
    startDate: formatYtDate(startDate),
    endDate: formatYtDate(endDate)
  };
}

function formatYtDate(date) {
  const year = date.getFullYear();
  const month = String(date.getMonth() + 1).padStart(2, '0');
  const day = String(date.getDate()).padStart(2, '0');
  return `${year}-${month}-${day}`;
}

function fetchYtPmaxPlacements() {
  console.log('Fetching PMAX YouTube placements...');
  try {
    const dateRange = getYtDateRange(YT_CONFIG.DATES_BACK);
    const query = `
      SELECT campaign.id, performance_max_placement_view.display_name, 
             performance_max_placement_view.placement, performance_max_placement_view.placement_type, 
             performance_max_placement_view.resource_name, performance_max_placement_view.target_url, 
             metrics.impressions
      FROM performance_max_placement_view
      WHERE metrics.impressions > ${YT_CONFIG.MIN_IMPRESSIONS}
        AND segments.date BETWEEN '${dateRange.startDate}' AND '${dateRange.endDate}'
        AND performance_max_placement_view.placement_type IN ('YOUTUBE_VIDEO', 'YOUTUBE_CHANNEL')
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
              channel_id: null,
              channel_handle: null,
              video_id: null
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
            reference_list: '',
            channel_id: null,
            channel_handle: null,
            video_id: null
          });
        }
      } catch (error) {
        console.error('Failed to fetch data from single account:', error);
        throw error;
      }
    }
    console.log(`Fetched ${placements.length} YouTube placements`);
    return placements;
  } catch (error) {
    console.error('Failed to fetch PMAX YouTube placements:', error);
    throw error;
  }
}

function checkMccVideoExclusion(placement) {
  if (!placement.target_url) return false;
  const video_id = extractVideoId(placement.target_url);
  const urls_to_check = [
    placement.target_url,
    video_id,
  ];
  if (video_id) {
    urls_to_check.push(
      `https://www.youtube.com/watch?v=${video_id}`,
      `https://youtu.be/${video_id}`,
      `youtube.com/video/${video_id}`
    );
  }
  for (const url of urls_to_check) {
    if (url && mcc_video_exclusions.has(url)) {
      placement.action = 'EXCLUDE';
      placement.reason = 'video found in MCC master exclusion list';
      placement.reference_list = extractYtListName(YT_CONFIG.MCC_VIDEO_EXCLUSION);
      return true;
    }
  }
  return false;
}

function generateNgrams(text, minN = 1, maxN = 3) {
  const ngrams = new Set();
  const words = text.toLowerCase()
    .replace(/[^\w\s]/g, ' ')
    .split(/\s+/)
    .filter(word => word.length > 0);
  for (let n = minN; n <= maxN; n++) {
    for (let i = 0; i <= words.length - n; i++) {
      const ngram = words.slice(i, i + n).join(' ');
      if (ngram.length >= YT_CONFIG.MIN_TERM_LENGTH) {
        ngrams.add(ngram);
      }
    }
  }
  return Array.from(ngrams);
}

function checkNegativeTerms(placement) {
  if (!placement.display_name) return false;
  const ngrams = generateNgrams(placement.display_name, YT_CONFIG.MIN_NGRAM, YT_CONFIG.MAX_NGRAM);
  const found_terms = [];
  const found_sources = new Set();
  ngrams.forEach(ngram => {
    if (negative_terms.has(ngram)) {
      found_terms.push(ngram);
      const sources = negative_terms.get(ngram);
      sources.forEach(source => found_sources.add(source));
    }
  });
  if (found_terms.length > 0) {
    const unique_terms = [...new Set(found_terms)];
    const source_names = Array.from(found_sources).map(source => extractYtListName(source));
    placement.action = 'EXCLUDE';
    placement.reason = `term/phrase detected: ${unique_terms.join(', ')}`;
    placement.reference_list = source_names.join(', ');
    return true;
  }
  return false;
}

function checkChannelBlacklist(placement) {
  const identifiers = extractChannelIdentifiers(placement);
  placement.channel_id = identifiers.channel_id;
  placement.channel_handle = identifiers.channel_handle;
  placement.video_id = identifiers.video_id;
  
  // Check channel ID (exact match)
  if (identifiers.channel_id && yt_channel_blacklist.has(identifiers.channel_id)) {
    const sources = yt_channel_blacklist.get(identifiers.channel_id);
    const source_names = sources.map(source => extractYtListName(source));
    placement.action = 'EXCLUDE';
    placement.reason = `excluded channel ID: ${identifiers.channel_id}`;
    placement.reference_list = source_names.join(', ');
    return true;
  }
  
  // Check channel handle with @ prefix
  if (identifiers.channel_handle) {
    const handle_with_at = `@${identifiers.channel_handle}`;
    if (yt_channel_blacklist.has(handle_with_at)) {
      const sources = yt_channel_blacklist.get(handle_with_at);
      const source_names = sources.map(source => extractYtListName(source));
      placement.action = 'EXCLUDE';
      placement.reason = `excluded channel handle: ${handle_with_at}`;
      placement.reference_list = source_names.join(', ');
      return true;
    }
    
    // Also check without @ prefix
    if (yt_channel_blacklist.has(identifiers.channel_handle)) {
      const sources = yt_channel_blacklist.get(identifiers.channel_handle);
      const source_names = sources.map(source => extractYtListName(source));
      placement.action = 'EXCLUDE';
      placement.reason = `excluded channel handle: ${identifiers.channel_handle}`;
      placement.reference_list = source_names.join(', ');
      return true;
    }
  }
  
  // Fuzzy matching for handles in URLs
  const sources = [placement.target_url, placement.placement].filter(Boolean);
  for (const source of sources) {
    for (const [identifier, blacklist_sources] of yt_channel_blacklist) {
      if (identifier.startsWith('@')) {
        const handle_without_at = identifier.substring(1);
        if (source.toLowerCase().includes(`@${handle_without_at.toLowerCase()}`) ||
            source.toLowerCase().includes(`/c/${handle_without_at.toLowerCase()}`) ||
            source.toLowerCase().includes(`/user/${handle_without_at.toLowerCase()}`)) {
          const source_names = blacklist_sources.map(source => extractYtListName(source));
          placement.action = 'EXCLUDE';
          placement.reason = `excluded channel (fuzzy match): ${identifier}`;
          placement.reference_list = source_names.join(', ');
          return true;
        }
      }
    }
  }
  
  return false;
}

function analyzeYtPlacements(placements) {
  console.log('Analyzing YouTube placements...');
  console.log(`Will fetch channel data from YouTube for up to ${Math.min(placements.length, YT_CONFIG.MAX_YOUTUBE_FETCHES)} videos`);
  console.log(`4-week cache enabled - cache stats will be shown at the end`);
  
  placements.forEach((placement, index) => {
    const identifiers = extractChannelIdentifiers(placement);
    placement.video_id = identifiers.video_id;
    placement.channel_id = identifiers.channel_id;
    placement.channel_handle = identifiers.channel_handle;
    
    if (checkMccVideoExclusion(placement)) return;
    if (checkNegativeTerms(placement)) return;
    if (checkChannelBlacklist(placement)) return;
  });
  
  const excluded_count = placements.filter(p => p.action === 'EXCLUDE').length;
  console.log(`Analysis complete: ${excluded_count}/${placements.length} placements flagged for exclusion`);
  console.log(`YouTube pages fetched: ${youtube_fetch_count}`);
  
  // Show cache statistics
  const cacheStats = youtubeChannelCache.getStats();
  console.log(`Cache statistics: ${cacheStats.hits} hits, ${cacheStats.misses} misses, ${cacheStats.hitRate} hit rate`);
  console.log(`Cache stores: ${cacheStats.stores}, Memory cache size: ${cacheStats.memorySize}`);
  
  const mcc_exclusions = placements.filter(p => p.reason && p.reason.includes('MCC master exclusion')).length;
  const term_exclusions = placements.filter(p => p.reason && p.reason.includes('term/phrase detected')).length;
  const channel_exclusions = placements.filter(p => p.reason && p.reason.includes('excluded channel')).length;
  
  console.log(`Exclusion breakdown: ${mcc_exclusions} MCC videos, ${term_exclusions} negative terms, ${channel_exclusions} blacklisted channels`);
}

function getCurrentEstDatetime() {
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

function createYtHyperlink(url, text) {
  return `=HYPERLINK("${url}","${text}")`;
}

function outputYtResults(placements, timings, start_time) {
  console.log('Outputting YouTube analysis results...');
  if (!YT_CONFIG.SHEET_URL || YT_CONFIG.SHEET_URL === 'YOUR_SHEET_URL_HERE') {
    console.error('Sheet URL not configured - please update YT_CONFIG.SHEET_URL');
    return;
  }
  try {
    const spreadsheet = SpreadsheetApp.openByUrl(YT_CONFIG.SHEET_URL);
    let yt_analysis_sheet = spreadsheet.getSheetByName('yt-exclusions');
    if (!yt_analysis_sheet) {
      yt_analysis_sheet = spreadsheet.insertSheet('yt-exclusions');
    }
    let yt_raw_sheet = spreadsheet.getSheetByName('yt_gaql_output');
    if (!yt_raw_sheet) {
      yt_raw_sheet = spreadsheet.insertSheet('yt_gaql_output');
      yt_raw_sheet.hideSheet();
    }
    let yt_reference_sheet = spreadsheet.getSheetByName('yt-reference-lists');
    if (!yt_reference_sheet) {
      yt_reference_sheet = spreadsheet.insertSheet('yt-reference-lists');
    }
    outputYtRawData(yt_raw_sheet, placements);
    outputYtAnalysisData(yt_analysis_sheet, placements, timings, start_time);
    outputYtReferenceLists(yt_reference_sheet);
  } catch (error) {
    console.error('Failed to output YouTube results:', error);
    throw error;
  }
}

function outputYtRawData(sheet, placements) {
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
    'Video ID',
    'Channel ID',
    'Channel Handle'
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
    placement.video_id || '',
    placement.channel_id || '',
    placement.channel_handle || ''
  ]);
  if (data.length > 0) {
    sheet.getRange(2, 1, data.length, headers.length).setValues(data);
  }
  sheet.getRange(1, 1, 1, headers.length).setFontWeight('bold');
  sheet.autoResizeColumns(1, headers.length);
}

function outputYtAnalysisData(sheet, placements, timings, start_time) {
  sheet.clear();
  const total_time = new Date() - start_time;
  const excluded_count = placements.filter(p => p.action === 'EXCLUDE').length;
  const current_datetime = getCurrentEstDatetime();
  const dateRange = getYtDateRange(YT_CONFIG.DATES_BACK);
  const unique_customers = [...new Set(placements.map(p => `${p.customer_name} - ${p.customer_id}`))];
  const customer_display = unique_customers.length > 0 ? unique_customers.join(', ') : 'No accounts found';
  
  // Get cache statistics for display
  const cacheStats = youtubeChannelCache.getStats();
  
  const summary_data = [
    [`Account: ${customer_display}`],
    [`YouTube Script Last Refresh: ${current_datetime}`],
    [`Script Total Runtime: ${(total_time / 1000).toFixed(2)} seconds`],
    [`Date Range: ${dateRange.startDate} to ${dateRange.endDate}`],
    [`Total YouTube Placements: ${placements.length} | Recommended Exclusions: ${excluded_count}`],
    [`Blacklist Stats: ${yt_channel_blacklist.size} channels, ${mcc_video_exclusions.size} videos, ${negative_terms.size} terms`],
    [`Analysis: N-gram range ${YT_CONFIG.MIN_NGRAM}-${YT_CONFIG.MAX_NGRAM}, Min term length: ${YT_CONFIG.MIN_TERM_LENGTH} | YouTube fetches: ${youtube_fetch_count}`],
    [`Cache: ${cacheStats.hitRate} hit rate, ${cacheStats.hits} hits, ${cacheStats.misses} misses, 4-week retention`]
  ];
  summary_data.forEach((row, index) => {
    sheet.getRange(index + 1, 1, 1, 1).setValue(row[0]);
  });
  sheet.getRange(1, 1, 1, 1).setFontWeight('bold');
  sheet.getRange(2, 1, 4, 1).setFontStyle('italic');
  const header_row = 10;
  const headers = [
    'Campaign ID',
    'Placement Type',
    'Video/Channel',
    'Impr.',
    'Display Name',
    'Action',
    'Reason',
    'Reference List',
    'Video ID',
    'Channel ID'
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
      placement.reference_list || '',
      placement.video_id || '',
      placement.channel_id || ''
    ]);
    sheet.getRange(header_row + 1, 1, data.length, headers.length).setValues(data);
    const action_range = sheet.getRange(header_row + 1, 6, data.length, 1);
    const exclude_rule = SpreadsheetApp.newConditionalFormatRule()
      .whenTextEqualTo('EXCLUDE')
      .setBackground('#ffcccc')
      .setRanges([action_range])
      .build();
    const rules = sheet.getConditionalFormatRules();
    rules.push(exclude_rule);
    sheet.setConditionalFormatRules(rules);
    sheet.setColumnWidth(3, 300);
    sheet.setColumnWidth(5, 250);
    sheet.setColumnWidth(7, 300);
    sheet.setColumnWidth(8, 200);
  }
  [1, 2, 4, 6, 9, 10].forEach(col => sheet.autoResizeColumn(col));
  console.log(`Output ${placements.length} YouTube rows to yt-exclusions sheet`);
}

function outputYtReferenceLists(sheet) {
  sheet.clear();
  const headers = ['Repository Name', 'Type', 'Size', 'URL'];
  sheet.getRange(1, 1, 1, headers.length).setValues([headers]);
  const reference_data = [];
  reference_data.push([
    extractYtListName(YT_CONFIG.MCC_VIDEO_EXCLUSION),
    'MCC Video Exclusions',
    mcc_video_exclusions.size,
    createYtHyperlink(YT_CONFIG.MCC_VIDEO_EXCLUSION, extractYtListName(YT_CONFIG.MCC_VIDEO_EXCLUSION))
  ]);
  const processed_channel_urls = new Set();
  for (const [channel, source_urls] of yt_channel_blacklist) {
    source_urls.forEach(url => {
      if (!processed_channel_urls.has(url)) {
        processed_channel_urls.add(url);
        const channels_from_this_source = Array.from(yt_channel_blacklist.entries())
          .filter(([c, urls]) => urls.includes(url)).length;
        reference_data.push([
          extractYtListName(url),
          'Channel Blacklist',
          channels_from_this_source,
          createYtHyperlink(url, extractYtListName(url))
        ]);
      }
    });
  }
  const processed_terms_urls = new Set();
  for (const [term, source_urls] of negative_terms) {
    source_urls.forEach(url => {
      if (!processed_terms_urls.has(url)) {
        processed_terms_urls.add(url);
        const terms_from_this_source = Array.from(negative_terms.entries())
          .filter(([t, urls]) => urls.includes(url)).length;
        reference_data.push([
          extractYtListName(url),
          'Negative Terms',
          terms_from_this_source,
          createYtHyperlink(url, extractYtListName(url))
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
  console.log(`Output ${reference_data.length} YouTube reference lists`);
}

function timeYtFunction(func) {
  const start = new Date();
  const result = func();
  return new Date() - start;
}

function logYtSummary(timings, total_placements, start_time) {
  const total_time = new Date() - start_time;
  const excluded_count = total_placements.filter ? total_placements.filter(p => p.action === 'EXCLUDE').length : 0;
  const cacheStats = youtubeChannelCache.getStats();
  
  console.log('\n=== YOUTUBE EXECUTION SUMMARY ===');
  console.log(`Total execution time: ${(total_time / 1000).toFixed(2)}s`);
  console.log(`Blacklist fetch: ${(timings.blacklist_fetch / 1000).toFixed(2)}s`);
  console.log(`YouTube fetch: ${(timings.yt_fetch / 1000).toFixed(2)}s`);
  console.log(`Analysis: ${(timings.analysis / 1000).toFixed(2)}s`);
  console.log(`Output: ${(timings.output / 1000).toFixed(2)}s`);
  console.log(`Total YouTube placements analyzed: ${Array.isArray(total_placements) ? total_placements.length : total_placements}`);
  console.log(`Placements flagged for exclusion: ${excluded_count}`);
  console.log(`YouTube pages fetched: ${youtube_fetch_count}`);
  console.log(`Cache performance: ${cacheStats.hitRate} hit rate (${cacheStats.hits} hits, ${cacheStats.misses} misses)`);
  console.log(`Cache efficiency: Saved ${cacheStats.hits} YouTube page fetches with 4-week retention`);
  console.log('=================================\n');
}

function main() {
  const start_time = new Date();
  console.log('Starting PMAX YouTube Placement Analysis with 4-Week Channel Caching...');
  const timings = {};
  let placements = [];
  
  try {
    // Fetch blacklists (includes cache cleanup)
    timings.blacklist_fetch = timeYtFunction(() => fetchAllYtBlacklists());
    
    // Fetch YouTube placements
    timings.yt_fetch = timeYtFunction(() => {
      placements = fetchYtPmaxPlacements();
      return placements;
    });
    
    // Analyze placements (includes YouTube page fetching with 4-week caching)
    timings.analysis = timeYtFunction(() => analyzeYtPlacements(placements));
    
    // Output results
    timings.output = timeYtFunction(() => outputYtResults(placements, timings, start_time));
    
    // Log summary
    logYtSummary(timings, placements, start_time);
    
  } catch (error) {
    console.error('YouTube script execution failed:', error);
    throw error;
  }
}
