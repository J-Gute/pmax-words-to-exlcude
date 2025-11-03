# utilize scrapingrobot.com API

scrape_youtube_channels_robot_enhanced <- function(queries, api_key, max_queries = 100, debug = FALSE) {
  
  library(httr)
  library(jsonlite)
  library(stringr)
  library(data.table)
  
  extract_channel_data_from_html <- function(html_content) {
    
    handle_patterns <- c(
      '/@([A-Za-z0-9_.-]+)',
      '"webCommandMetadata":\\{"url":"/@([A-Za-z0-9_.-]+)"',
      '"canonicalChannelUrl":"https://www\\.youtube\\.com/@([A-Za-z0-9_.-]+)"',
      '"url":"/@([A-Za-z0-9_.-]+)"',
      '"browseEndpoint":\\{"browseId":"@([A-Za-z0-9_.-]+)"',
      '"navigationEndpoint":\\{"commandMetadata":\\{"webCommandMetadata":\\{"url":"/@([A-Za-z0-9_.-]+)"',
      '"shortBylineText":[^}]*"/@([A-Za-z0-9_.-]+)"',
      '"ownerText":[^}]*"/@([A-Za-z0-9_.-]+)"',
      '"longBylineText":[^}]*"/@([A-Za-z0-9_.-]+)"',
      '"reelWatchEndpoint":[^}]*"/@([A-Za-z0-9_.-]+)"'
    )
    
    channel_patterns <- c(
      '/channel/([A-Za-z0-9_-]{24})',
      '"channelId":"([A-Za-z0-9_-]{24})"',
      '"browseEndpoint":\\{"browseId":"([A-Za-z0-9_-]{24})"',
      '"browseId":"([A-Za-z0-9_-]{24})"',
      '"externalChannelId":"([A-Za-z0-9_-]{24})"',
      '"shortBylineText":[^}]*"/channel/([A-Za-z0-9_-]{24})"',
      '"ownerText":[^}]*"/channel/([A-Za-z0-9_-]{24})"',
      '"longBylineText":[^}]*"/channel/([A-Za-z0-9_-]{24})"',
      '"reelWatchEndpoint":[^}]*"/channel/([A-Za-z0-9_-]{24})"',
      '"channelNavigationEndpoint":[^}]*"([A-Za-z0-9_-]{24})"'
    )
    
    all_handles <- str_extract_all(html_content, paste(handle_patterns, collapse = "|"))[[1]] |>
      str_extract("([A-Za-z0-9_.-]+)$") |>
      {\(x) x[!is.na(x) & x != ""]}() |>
      unique()
    
    all_channel_ids <- str_extract_all(html_content, paste(channel_patterns, collapse = "|"))[[1]] |>
      str_extract("([A-Za-z0-9_-]{24})$") |>
      {\(x) x[!is.na(x) & x != ""]}() |>
      unique()
    
    yt_data_match <- str_extract(html_content, 'var ytInitialData = (\\{.*?\\});')
    
    if(!is.na(yt_data_match)) {
      tryCatch({
        json_str <- str_extract(yt_data_match, '\\{.*\\}')
        
        json_handle_patterns <- c(
          '/@([A-Za-z0-9_.-]+)',
          '"@([A-Za-z0-9_.-]+)"',
          '"handle":"@([A-Za-z0-9_.-]+)"'
        )
        
        json_id_patterns <- c(
          '/channel/([A-Za-z0-9_-]{24})',
          '"([A-Za-z0-9_-]{24})"'
        )
        
        json_handles <- str_extract_all(json_str, paste(json_handle_patterns, collapse = "|"))[[1]] |>
          str_extract("([A-Za-z0-9_.-]+)$") |>
          {\(x) x[!is.na(x) & x != ""]}()
        
        json_ids <- str_extract_all(json_str, paste(json_id_patterns, collapse = "|"))[[1]] |>
          str_extract("([A-Za-z0-9_-]{24})$") |>
          {\(x) x[!is.na(x) & x != "" & nchar(x) == 24]}() 
        
        all_handles <- c(all_handles, json_handles) |> unique()
        all_channel_ids <- c(all_channel_ids, json_ids) |> unique()
        
      }, error = function(e) {
        if(debug) cat("Debug - ytInitialData extraction failed\n")
      })
    }
    
    shorts_indicators <- c('"shorts"', '"reelWatchEndpoint"', '"shortBylineText"', '"reelItemRenderer"')
    
    if(any(str_detect(html_content, shorts_indicators))) {
      
      shorts_blocks <- str_extract_all(html_content, '"reelItemRenderer":\\{[^}]*\\}')[[1]]
      
      for(block in shorts_blocks) {
        shorts_handles <- str_extract_all(block, '/@([A-Za-z0-9_.-]+)')[[1]] |>
          str_remove("^/@") |>
          {\(x) x[!is.na(x) & x != ""]}()
        
        shorts_ids <- str_extract_all(block, '/channel/([A-Za-z0-9_-]{24})')[[1]] |>
          str_remove("^/channel/") |>
          {\(x) x[!is.na(x) & x != ""]}()
        
        all_handles <- c(all_handles, shorts_handles) |> unique()
        all_channel_ids <- c(all_channel_ids, shorts_ids) |> unique()
      }
      
      if(debug && length(shorts_blocks) > 0) {
        cat("Debug - Found", length(shorts_blocks), "shorts blocks\n")
      }
    }
    
    list(
      handles = all_handles,
      channel_ids = all_channel_ids
    )
  }
  
  scrape_single_query <- function(query, query_index, total_queries) {
    
    encoded_query <- URLencode(query, reserved = TRUE)
    youtube_url <- paste0("https://www.youtube.com/results?search_query=", encoded_query, 
                          "&sp=CAMSBAgFEAE%253D") # sp order by most viewed, videos only, and posted last 12 months - adjust as needed
    
    scraping_robot_url <- paste0(
      "https://api.scrapingrobot.com/?token=", api_key, 
      "&url=", URLencode(youtube_url, reserved = TRUE)
    )
    
    if(debug) {
      cat("Debug - Query:", query, "\n")
      cat("Debug - Final API URL:", scraping_robot_url, "\n")
    }
    
    tryCatch({
      
      response <- GET(scraping_robot_url, timeout(60))
      
      if(debug) {
        cat("Debug - Status code:", status_code(response), "\n")
      }
      
      if(status_code(response) != 200) {
        cat("Query", query_index, "HTTP", status_code(response), "\n")
        return(list(handles = character(0), channel_ids = character(0)))
      }
      
      json_response <- content(response, "parsed", type = "application/json")
      
      if(debug) {
        cat("Debug - JSON keys:", paste(names(json_response), collapse = ", "), "\n")
      }
      
      html_content <- ""
      
      # Use the original method for extracting content
      if("result" %in% names(json_response)) {
        html_content <- json_response$result
      } else if("html" %in% names(json_response)) {
        html_content <- json_response$html
      } else if("content" %in% names(json_response)) {
        html_content <- json_response$content
      } else if("data" %in% names(json_response)) {
        html_content <- json_response$data
      } else {
        html_content <- toJSON(json_response, auto_unbox = TRUE)
      }
      
      if(debug) {
        cat("Debug - HTML content length:", nchar(html_content), "\n")
        cat("Debug - First 200 chars:", str_sub(html_content, 1, 200), "\n")
      }
      
      if(is.null(html_content) || html_content == "" || nchar(html_content) < 100) {
        cat("Query", query_index, "empty or invalid response\n")
        return(list(handles = character(0), channel_ids = character(0)))
      }
      
      # Use original blocking detection - more conservative
      serious_blocks <- c(
        "access denied", "forbidden", "rate limit exceeded",
        "captcha required", "unusual traffic detected",
        "your request appears to be automated"
      )
      
      if(any(str_detect(tolower(html_content), serious_blocks))) {
        cat("Query", query_index, "serious blocking detected\n")
        return(list(handles = character(0), channel_ids = character(0)))
      }
      
      # Use original YouTube validation
      youtube_indicators <- c(
        "youtube", "ytInitialData", "var ytInitialPlayerResponse",
        "www.youtube.com", "yt-formatted-string"
      )
      
      if(!any(str_detect(html_content, youtube_indicators))) {
        cat("Query", query_index, "doesn't appear to be YouTube content\n")
        return(list(handles = character(0), channel_ids = character(0)))
      }
      
      channel_data <- extract_channel_data_from_html(html_content)
      
      # Check for shorts content in debug mode
      if(debug) {
        shorts_count <- str_count(html_content, '"shorts"')
        reel_count <- str_count(html_content, '"reelItemRenderer"')
        cat("Debug - Shorts references:", shorts_count, "Reel items:", reel_count, "\n")
      }
      
      cat("Query", query_index, "/", total_queries, "- Found", 
          length(channel_data$handles), "handles,", 
          length(channel_data$channel_ids), "IDs\n")
      
      return(channel_data)
      
    }, error = function(e) {
      cat("Query", query_index, "failed:", str_sub(e$message, 1, 50), "\n")
      if(debug) {
        cat("Debug - Full error:", e$message, "\n")
      }
      return(list(handles = character(0), channel_ids = character(0)))
    })
  }
  
  
  safe_queries <- if(length(queries) > max_queries) {
    cat("Processing", max_queries, "of", length(queries), "queries\n")
    sample(queries, max_queries)
  } else {
    queries
  }
  
  cat("Starting enhanced ScrapingRobot extraction for", length(safe_queries), "queries\n")
  cat("Enhanced for shorts content detection\n")
  
  all_results <- list()
  successful_queries <- 0
  
  for(i in seq_along(safe_queries)) {
    query <- safe_queries[i]
    
    # if(i > 1) Sys.sleep(runif(1, 1, 3)) testing with wait time - not needed
    
    result <- scrape_single_query(query, i, length(safe_queries))
    all_results[[query]] <- result
    
    if(length(result$handles) > 0 || length(result$channel_ids) > 0) {
      successful_queries <- successful_queries + 1
    }
  }

  all_handles <- lapply(all_results, function(x) x$handles) |> unlist() |> unique()
  all_channel_ids <- lapply(all_results, function(x) x$channel_ids) |> unlist() |> unique()
  
  success_rate <- round(successful_queries / length(safe_queries) * 100, 2)
  
  results_dt <- data.table(
    type = c(rep("handle", length(all_handles)), rep("channel_id", length(all_channel_ids))),
    identifier = c(all_handles, all_channel_ids)
  )
  
  cat("Enhanced ScrapingRobot extraction complete!\n")
  cat("Success rate:", success_rate, "%\n")
  cat("Unique handles:", length(all_handles), "\n")
  cat("Unique channel IDs:", length(all_channel_ids), "\n")
  cat("Total unique identifiers:", nrow(results_dt), "\n")
  cat("Channels per query", round((nrow(results_dt) / length(queries))), 2)
  
  list(
    by_query = all_results,
    results_dt = results_dt,
    all_handles = all_handles,
    all_channel_ids = all_channel_ids,
    success_rate = success_rate,
    queries_used = length(safe_queries)
  )
}
