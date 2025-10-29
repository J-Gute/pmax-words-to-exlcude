# try to scrape youtube query results for channel handles or ids
# works with <=30 queries, start expereincing rate-limiting beyond that

fetch_youtube_minimal_footprint <- function(queries, max_queries = 10) {
  
  library(httr2)
  library(rvest)
  library(stringr)
  library(dplyr)
  library(purrr)
  
  get_stealth_headers <- function() {
    browser_profiles <- list(
      chrome_windows = list(
        `User-Agent` = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        `Sec-Ch-Ua` = '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
        `Sec-Ch-Ua-Platform` = '"Windows"'
      ),
      firefox_windows = list(
        `User-Agent` = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
        `Sec-Fetch-Site` = "none"
      ),
      safari_mac = list(
        `User-Agent` = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
        `Sec-Fetch-Site` = "none"
      )
    )
    
    profile <- sample(browser_profiles, 1)[[1]]
    
    base_headers <- list(
      `Accept` = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
      `Accept-Language` = "en-US,en;q=0.5",
      `Accept-Encoding` = "gzip, deflate",
      `Connection` = "keep-alive",
      `Upgrade-Insecure-Requests` = "1"
    )
    
    return(c(profile, base_headers))
  }
  
  # Minimal query encoding - avoid over-encoding
  encode_query_minimal <- function(query) {
    query |>
      str_replace_all("\\s+", "+") |>
      str_replace_all("&", "%26") |>
      str_replace_all("#", "%23")
  }
  
  get_endpoint_variant <- function(query) {
    endpoints <- c(
      paste0("https://www.youtube.com/results?search_query=", query),
      paste0("https://m.youtube.com/results?search_query=", query),  # Mobile endpoint
      paste0("https://www.youtube.com/results?search_query=", query, "&hl=en")  # Language hint
    )
    sample(endpoints, 1)
  }
  
  human_like_delay <- function() {
    delay_patterns <- c(
      runif(1, 1.2, 3.5),    # Quick browsing
      runif(1, 4, 8),        # Reading/thinking
      runif(1, 8, 15)        # Longer pause
    )
    
    selected_delay <- sample(delay_patterns, 1, prob = c(0.5, 0.3, 0.2))
    Sys.sleep(selected_delay)
  }
  
  extract_channels_minimal <- function(query, index, total) {
    max_attempts <- 2 
    
    for(attempt in 1:max_attempts) {
      tryCatch({
        human_like_delay()
      
        encoded_query <- encode_query_minimal(query)
        url <- get_endpoint_variant(encoded_query)
      
        headers <- get_stealth_headers()
        
        req <- httr2::request(url) |>
          httr2::req_timeout(30)  

        for(name in names(headers)) {
          req <- httr2::req_headers(req, !!name := headers[[name]])
        }

        response <- httr2::req_perform(req)

        Sys.sleep(runif(1, 0.3, 0.8))
        
        raw_html <- httr2::resp_body_string(response)
        
        handles <- str_extract_all(raw_html, '/@([A-Za-z0-9_.-]+)')[[1]] |>
          str_remove('^/@') |>
          unique()
        
        channel_ids <- str_extract_all(raw_html, '/channel/([A-Za-z0-9_-]{24})')[[1]] |>
          str_remove('^/channel/') |>
          unique()
  
        short_channel_ids <- str_extract_all(raw_html, '/channel/([A-Za-z0-9_-]{10,})')[[1]] |>
          str_remove('^/channel/') |>
          unique()
        
        all_channel_ids <- c(channel_ids, short_channel_ids) |> unique()
        
        cat("Query", index, "/", total, ":", substr(query, 1, 30), 
            "- Found:", length(handles), "handles,", length(all_channel_ids), "IDs\n")
        
        return(list(
          handles = handles,
          channel_ids = all_channel_ids
        ))
        
      }, error = function(e) {
        if(str_detect(e$message, "400|403|429")) {
          cat("Rate limited on query", index, "- Cooling down...\n")
          Sys.sleep(runif(1, 30, 60))  
        } else {
          cat("Error query", index, "attempt", attempt, ":", e$message, "\n")
        }
        
        if(attempt < max_attempts) {
          Sys.sleep(runif(1, 5, 10))  
        }
      })
    }
    
    return(list(handles = character(0), channel_ids = character(0)))
  }

  cat("Minimal footprint processing of", min(length(queries), max_queries), "queries\n")

  safe_queries <- sample(queries, min(length(queries), max_queries))
  
  results <- list()
  
  for(i in seq_along(safe_queries)) {
    query <- safe_queries[i]
    result <- extract_channels_minimal(query, i, length(safe_queries))
    results[[query]] <- result
  
    if(i %% sample(3:5, 1) == 0 && i < length(safe_queries)) {
      break_time <- runif(1, 15, 45)
      cat("Taking break:", round(break_time, 1), "seconds...\n")
      Sys.sleep(break_time)
    }
  }
  
  all_handles <- map(results, ~ .x$handles) |> unlist() |> unique()
  all_channel_ids <- map(results, ~ .x$channel_ids) |> unlist() |> unique()
  
  cat("Completed! Found", length(all_handles), "handles,", length(all_channel_ids), "channel IDs\n")
  
  return(list(
    by_query = results,
    all_handles = all_handles,
    all_channel_ids = all_channel_ids
  ))
}
