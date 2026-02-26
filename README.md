# DNS Filter Agent for Emergence System

## Overview

The **DNS Filter Agent** (`dns_filter_app`) is a lightweight DNS resolution component for the **Emergence System**. Its primary role is to resolve domain names and return structured DNS information (embryos) for further processing by other Emergence modules.

---

## Features

- **DNS Record Support:** Handles `A`, `AAAA`, `MX`, `NS`, `TXT`, and `CNAME` record types.  
- **Dual Resolver:** Uses `inet:gethostbyname` for IPv4 and `inet_res:lookup/3` for all other types.  
- **Crash-Safe:** All DNS resolution and parsing operations are wrapped to avoid process crashes.  
- **Caching:** Responses are cached in memory with a configurable TTL (default 60 seconds).  
- **Cross-Platform:** Works on Windows, Linux, and macOS.  
- **Minimal Logging:** Only critical messages are logged, and the final list of embryos is output for debugging.

---

## How It Works

1. **Receiving Queries:**  
   The agent receives a binary string (domain name) from Emergence’s filter pipeline.  

2. **Domain Extraction:**  
   - The agent validates the input and extracts a domain name using a regex-based strategy.  
   - Invalid or malformed input results in an empty response.  

3. **Cache Check:**  
   - The agent checks its in-memory cache for existing embryos.  
   - If present and not expired, the cached embryos are returned immediately.  

4. **DNS Resolution Pipeline:**  
   - Each supported DNS record type is queried in sequence.  
   - IPv4 (`A`) records use `inet:gethostbyname`.  
   - All other types use `inet_res:lookup/3`.  
   - Resolution failures are handled gracefully, and missing record types are skipped.  

5. **Embryo Generation:**  
   - Each successful DNS record is transformed into an **embryo**: a map containing the domain, type, and properties (e.g., IP addresses or MX hosts).  
   - The embryos are collected into a list, cached, and returned.  

6. **Logging:**  
   - Only final embryo lists and cache misses are logged, minimizing noise in production.  

---

## Configuration

- **Cache TTL:** Controlled via the `?CACHE_TTL_S` macro (default `60` seconds).  
- **Supported Record Types:** Controlled via the `?RECORD_TYPES` macro.  

---

## Usage in Emergence

```erlang
{Embryos, NewMemory} = dns_filter_app:handle(<<"example.com">>, Memory).
```

- `Embryos` – list of DNS embryos.  
- `NewMemory` – updated cache state.  

This makes the DNS agent a **plug-and-play module** for resolving domain information in Emergence pipelines.

