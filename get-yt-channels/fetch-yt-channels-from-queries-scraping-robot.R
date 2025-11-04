# utilize scrapingrobot.com API

scrape_youtube_channels_robot_enhanced <- function(queries, api_key, max_queries = 100, debug = FALSE) {
  
  library(httr)
  library(jsonlite)
  library(stringr)
  library(data.table)
  
  extract_channel_data_from_html <- function(html_content) {

    channel_patterns <- c(
      '"channelId":"([A-Za-z0-9_-]{24})"',
      '"browseId":"([A-Za-z0-9_-]{24})"',
      '"externalChannelId":"([A-Za-z0-9_-]{24})"',
      '"browseEndpoint":\\{"browseId":"([A-Za-z0-9_-]{24})"',
      '"channelNavigationEndpoint":[^}]*"([A-Za-z0-9_-]{24})"',
      '"videoOwnerRenderer":[^}]*"([A-Za-z0-9_-]{24})"',
      '"ownerBadges":[^}]*"([A-Za-z0-9_-]{24})"',
      'data-channel-external-id="([A-Za-z0-9_-]{24})"',
      '"externalId":"([A-Za-z0-9_-]{24})"',
      'l_id="([A-Za-z0-9_-]{24})"',
      '<meta itemprop="channelId" content="([A-Za-z0-9_-]{24})">',
      '"shortBylineText":[^}]*"([A-Za-z0-9_-]{24})"',
      '"ownerText":[^}]*"([A-Za-z0-9_-]{24})"',
      '"longBylineText":[^}]*"([A-Za-z0-9_-]{24})"',
      '"reelWatchEndpoint":[^}]*"([A-Za-z0-9_-]{24})"',
      '"/channel/([A-Za-z0-9_-]{24})"',
      '"https://www\\.youtube\\.com/channel/([A-Za-z0-9_-]{24})"'
    )
  
    handle_patterns <- c(
      '"canonicalChannelUrl":"https://www\\.youtube\\.com/@([A-Za-z0-9_.-]+)"',
      '"webCommandMetadata":\\{"url":"/@([A-Za-z0-9_.-]+)"',
      '"url":"/@([A-Za-z0-9_.-]+)"',
      '"browseEndpoint":\\{"browseId":"@([A-Za-z0-9_.-]+)"',
      '"navigationEndpoint":\\{"commandMetadata":\\{"webCommandMetadata":\\{"url":"/@([A-Za-z0-9_.-]+)"',
      '"/@([A-Za-z0-9_.-]+)"',
      '"shortBylineText":[^}]*"/@([A-Za-z0-9_.-]+)"',
      '"ownerText":[^}]*"/@([A-Za-z0-9_.-]+)"',
      '"longBylineText":[^}]*"/@([A-Za-z0-9_.-]+)"',
      '"reelWatchEndpoint":[^}]*"/@([A-Za-z0-9_.-]+)"'
    )
    
    all_channel_ids <- character(0)
    
    pattern_matches <- str_extract_all(html_content, paste(channel_patterns, collapse = "|"))[[1]]
    
    if(length(pattern_matches) > 0) {
      extracted_ids <- str_extract(pattern_matches, "([A-Za-z0-9_-]{24})")
      valid_ids <- extracted_ids[!is.na(extracted_ids) & nchar(extracted_ids) == 24]
      all_channel_ids <- c(all_channel_ids, valid_ids)
    }
    
    uc_quoted_patterns <- c(
      '"(UC[A-Za-z0-9_-]{22})"',  
      "'(UC[A-Za-z0-9_-]{22})'", 
      '"UC[A-Za-z0-9_-]{22}"',   
      "'UC[A-Za-z0-9_-]{22}'" 
    )
    
    for(pattern in uc_quoted_patterns) {
      uc_matches <- str_extract_all(html_content, pattern)[[1]]
      if(length(uc_matches) > 0) {
        extracted_uc <- str_extract(uc_matches, "UC[A-Za-z0-9_-]{22}")
        valid_uc_ids <- extracted_uc[!is.na(extracted_uc) & nchar(extracted_uc) == 24]
        all_channel_ids <- c(all_channel_ids, valid_uc_ids)
        
        if(debug && length(valid_uc_ids) > 0) {
          cat("Debug - UC pattern", pattern, "found:", length(valid_uc_ids), "IDs\n")
        }
      }
    }
    
    yt_data_match <- str_extract(html_content, 'var ytInitialData = (\\{.*?\\});')
    
    if(!is.na(yt_data_match)) {
      tryCatch({
        json_str <- str_extract(yt_data_match, '\\{.*\\}')
      
          json_uc_matches <- str_extract_all(json_str, pattern)[[1]]
          if(length(json_uc_matches) > 0) {
            extracted_uc <- str_extract(json_uc_matches, "UC[A-Za-z0-9_-]{22}")
            valid_json_uc <- extracted_uc[!is.na(extracted_uc) & nchar(extracted_uc) == 24]
            all_channel_ids <- c(all_channel_ids, valid_json_uc)
          }
        }
        
        json_id_patterns <- c(
          '"channelId":"([A-Za-z0-9_-]{24})"',
          '"browseId":"([A-Za-z0-9_-]{24})"',
          '"externalChannelId":"([A-Za-z0-9_-]{24})"',
          '"externalId":"([A-Za-z0-9_-]{24})"',
          '"/channel/([A-Za-z0-9_-]{24})"'
        )
        
        json_ids <- str_extract_all(json_str, paste(json_id_patterns, collapse = "|"))[[1]] |>
          str_extract("([A-Za-z0-9_-]{24})") |>
          {\(x) x[!is.na(x) & x != "" & nchar(x) == 24]}()
        
        all_channel_ids <- c(all_channel_ids, json_ids)
        
        if(debug) {
          cat("Debug - JSON quoted patterns found:", length(json_ids), "IDs\n")
        }
        
      }, error = function(e) {
        if(debug) cat("Debug - ytInitialData extraction failed\n")
      })
    }
  
    aggressive_quoted_patterns <- c(
      '["\'](UC[A-Za-z0-9_-]{22})["\']',  # Any quotes around UC ID
      '"UC[A-Za-z0-9_-]{22}"',             # Double quotes
      "'UC[A-Za-z0-9_-]{22}'",             # Single quotes
      '"/channel/(UC[A-Za-z0-9_-]{22})"',
      '"/c/(UC[A-Za-z0-9_-]{22})"',
      ':\\s*"(UC[A-Za-z0-9_-]{22})"',
      '=\\s*"(UC[A-Za-z0-9_-]{22})"'
    )
    
    for(pattern in aggressive_quoted_patterns) {
      aggressive_matches <- str_extract_all(html_content, pattern)[[1]]
      if(length(aggressive_matches) > 0) {
        extracted_uc <- str_extract(aggressive_matches, "UC[A-Za-z0-9_-]{22}")
        valid_aggressive_uc <- extracted_uc[!is.na(extracted_uc) & nchar(extracted_uc) == 24]
        all_channel_ids <- c(all_channel_ids, valid_aggressive_uc)
        
        if(debug && length(valid_aggressive_uc) > 0) {
          cat("Debug - Aggressive quoted pattern", pattern, "found:", length(valid_aggressive_uc), "IDs\n")
        }
      }
    }
    
    # Clean and deduplicate channel IDs
    all_channel_ids <- all_channel_ids[!is.na(all_channel_ids) & nchar(all_channel_ids) == 24] |>
      unique()
    
    all_handles <- str_extract_all(html_content, paste(handle_patterns, collapse = "|"))[[1]] |>
      str_extract("([A-Za-z0-9_.-]+)") |>
      {\(x) x[!is.na(x) & x != ""]}() |>
      unique()
    
    if(debug) {
      cat("Debug - Total unique quoted channel IDs found:", length(all_channel_ids), "\n")
      cat("Debug - Total unique handles found:", length(all_handles), "\n")
      
      uc_count <- sum(str_detect(all_channel_ids, "^UC"))
      non_uc_count <- length(all_channel_ids) - uc_count
      cat("Debug - UC prefixed IDs:", uc_count, "Non-UC IDs:", non_uc_count, "\n")
      
      if(length(all_channel_ids) > 0) {
        cat("Debug - Sample channel IDs:", paste(head(all_channel_ids, 3), collapse = ", "), "\n")
      }
    }
    
    list(
      channel_ids = all_channel_ids,
      handles = all_handles
    )
  }
  
  # Single query function
  scrape_single_query <- function(query, query_index, total_queries) {
    
    encoded_query <- URLencode(query, reserved = TRUE)
    youtube_url <- paste0("https://www.youtube.com/results?search_query=", encoded_query, 
                          "&sp=CAMSBAgFEAE%253D")
    
    scraping_robot_url <- paste0(
      "https://api.scrapingrobot.com/?token=", api_key, 
      "&url=", URLencode(youtube_url, reserved = TRUE)
    )
    
    if(debug) {
      cat("Debug - Query:", query, "\n")
    }
    
    tryCatch({
      
      response <- GET(scraping_robot_url, timeout(60))
      
      if(status_code(response) != 200) {
        cat("Query", query_index, "HTTP", status_code(response), "\n")
        return(list(channel_ids = character(0), handles = character(0)))
      }
      
      json_response <- content(response, "parsed", type = "application/json")
      
      html_content <- ""
      
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
      
      if(is.null(html_content) || html_content == "" || nchar(html_content) < 100) {
        cat("Query", query_index, "empty or invalid response\n")
        return(list(channel_ids = character(0), handles = character(0)))
      }
      
      # Basic validation
      serious_blocks <- c(
        "access denied", "forbidden", "rate limit exceeded",
        "captcha required", "unusual traffic detected"
      )
      
      if(any(str_detect(tolower(html_content), serious_blocks))) {
        cat("Query", query_index, "serious blocking detected\n")
        return(list(channel_ids = character(0), handles = character(0)))
      }
      
      youtube_indicators <- c("youtube", "ytInitialData", "www.youtube.com")
      
      if(!any(str_detect(html_content, youtube_indicators))) {
        cat("Query", query_index, "doesn't appear to be YouTube content\n")
        return(list(channel_ids = character(0), handles = character(0)))
      }
      
      channel_data <- extract_channel_data_from_html(html_content)
      
      cat("Query", query_index, "/", total_queries, "- Found", 
          length(channel_data$channel_ids), "IDs,", 
          length(channel_data$handles), "handles\n")
      
      return(channel_data)
      
    }, error = function(e) {
      cat("Query", query_index, "failed:", str_sub(e$message, 1, 50), "\n")
      return(list(channel_ids = character(0), handles = character(0)))
    })
  }
  
  # Main execution
  safe_queries <- if(length(queries) > max_queries) {
    cat("Processing", max_queries, "of", length(queries), "queries\n")
    sample(queries, max_queries)
  } else {
    queries
  }
  
  cat("Starting quoted UC-focused ScrapingRobot extraction for", length(safe_queries), "queries\n")
  cat("Updated Channel ID Method: Requiring all 24-character IDs to appear in quotes\n")
  
  all_results <- list()
  successful_queries <- 0
  
  for(i in seq_along(safe_queries)) {
    query <- safe_queries[i]
    
    result <- scrape_single_query(query, i, length(safe_queries))
    all_results[[query]] <- result
    
    if(length(result$channel_ids) > 0 || length(result$handles) > 0) {
      successful_queries <- successful_queries + 1
    }
  }

  # final output - return a df instead of list
  query_channel_df <- data.frame()
  
  for(query_name in names(all_results)) {
    result <- all_results[[query_name]]
    
    if(length(result$channel_ids) > 0) {
      sorted_ids <- result$channel_ids[order(!str_detect(result$channel_ids, "^UC"), result$channel_ids)]
      channel_urls <- paste0("https://www.youtube.com/channel/", sorted_ids)
      query_channel_df <- rbind(query_channel_df, 
                                data.frame(query = query_name, 
                                           channel = channel_urls,
                                           stringsAsFactors = FALSE))
    }
    
    if(length(result$handles) > 0) {
      handle_urls <- paste0("https://www.youtube.com/@", result$handles)
      query_channel_df <- rbind(query_channel_df, 
                                data.frame(query = query_name, 
                                           channel = handle_urls,
                                           stringsAsFactors = FALSE))
    }
  }
  
  # Summary stats
  all_channel_ids <- lapply(all_results, function(x) x$channel_ids) |> unlist() |> unique()
  all_handles <- lapply(all_results, function(x) x$handles) |> unlist() |> unique()
  
  uc_ids <- all_channel_ids[str_detect(all_channel_ids, "^UC")]
  non_uc_ids <- all_channel_ids[!str_detect(all_channel_ids, "^UC")]
  
  success_rate <- round(successful_queries / length(safe_queries) * 100, 2)
  
  cat("Quoted UC-focused ScrapingRobot extraction complete!\n")
  cat("Success rate:", success_rate, "%\n")
  cat("UC-prefixed channel IDs:", length(uc_ids), "\n")
  cat("Other channel IDs:", length(non_uc_ids), "\n")
  cat("Total unique channel IDs:", length(all_channel_ids), "\n")
  cat("Unique handles:", length(all_handles), "\n")
  cat("Total query-channel pairs:", nrow(query_channel_df), "\n")
  
  return(query_channel_df)
}
