.ip2whois_env <- new.env(parent = emptyenv())

#' @title Set IP2Location.io API key
#'
#' @description Set IP2Location.io API key for lookup. Free API key can be obtained from <https://www.ip2location.io/sign-up?ref=1/>
#' @param api_key IP2Location.io API key
#' @return No return value, called for side effects.
#' @import reticulate
#' @export
#' @examples \dontrun{
#' set_api_key("YOUR_API_KEY")
#' }
#'

set_api_key <- function(api_key) {
  .ip2whois_env$ip2whois <- reticulate::import("ip2whois")
  .ip2whois_env$ip2whois_init <- .ip2whois_env$ip2whois$Api(api_key)
}

#' @title Get the current IP2WHOIS API object
#'
#' @description Retrieve the Python \code{ip2whois.Api} object created by \code{set_api_key()}. Internal helper used by the lookup functions to ensure an API key has been set before making a request.
#' @return Return the Python ip2whois API object used for lookups
#' @keywords internal
#' @noRd
#'

.getInit <- function() {
  if (is.null(.ip2whois_env$ip2whois_init)) {
    stop("API key not set. Please call set_api_key() first.")
  }
  .ip2whois_env$ip2whois_init
}

#' @title Lookup for WHOIS information
#'
#' @description Lookup for a comprehensive of the WHOIS information
#' @param domain domain name to lookup for
#' @return Return the WHOIS information about the domain
#' @import reticulate
#' @export
#' @examples \dontrun{
#' lookup("example.com")
#' }
#'

lookup <- function(domain){
  ip2whois_init <- .getInit()
  rec <- ip2whois_init$lookup(domain)
  result <- reticulate::py_to_r(rec)
  return(result)
}

#' @title Lookup for registrar information
#'
#' @description Lookup for registrar information
#' @param domain domain name to lookup for
#' @return Return the registrar information of the domain
#' @import reticulate
#' @export
#' @examples \dontrun{
#' lookupRegistrar("example.com")
#' }
#'

lookupRegistrar <- function(domain){
  rec <- lookup(domain)
  return(rec$registrar)
}

#' @title Lookup for registrant information
#'
#' @description Lookup for registrant information
#' @param domain domain name to lookup for
#' @return Return the registrant information of the domain
#' @import reticulate
#' @export
#' @examples \dontrun{
#' lookupRegistrant("example.com")
#' }
#'

lookupRegistrant <- function(domain){
  rec <- lookup(domain)
  return(rec$registrant)
}

#' @title Lookup for admin information
#'
#' @description Lookup for admin information
#' @param domain domain name to lookup for
#' @return Return the admin information of the domain
#' @import reticulate
#' @export
#' @examples \dontrun{
#' lookupAdmin("example.com")
#' }
#'

lookupAdmin <- function(domain){
  rec <- lookup(domain)
  return(rec$admin)
}

#' @title Lookup for tech information
#'
#' @description Lookup for tech information
#' @param domain domain name to lookup for
#' @return Return the tech information of the domain
#' @import reticulate
#' @export
#' @examples \dontrun{
#' lookupTech("example.com")
#' }
#'

lookupTech <- function(domain){
  rec <- lookup(domain)
  return(rec$tech)
}

#' @title Lookup for billing information
#'
#' @description Lookup for billing information
#' @param domain domain name to lookup for
#' @return Return the billing information of the domain
#' @import reticulate
#' @export
#' @examples \dontrun{
#' lookupBilling("example.com")
#' }
#'

lookupBilling <- function(domain){
  rec <- lookup(domain)
  return(rec$billing)
}

#' @title Lookup for nameservers information
#'
#' @description Lookup for nameservers information
#' @param domain domain name to lookup for
#' @return Return the nameservers information of the domain
#' @import reticulate
#' @export
#' @examples \dontrun{
#' lookupNameservers("example.com")
#' }
#'

lookupNameservers <- function(domain){
  rec <- lookup(domain)
  return(rec$nameservers)
}

#' @title Lookup for whois server information
#'
#' @description Lookup for whois server information
#' @param domain domain name to lookup for
#' @return Return the whois server information of the domain
#' @import reticulate
#' @export
#' @examples \dontrun{
#' lookupWhoisServer("example.com")
#' }
#'

lookupWhoisServer <- function(domain){
  rec <- lookup(domain)
  return(rec$whois_server)
}


#' @title Get Punycode for domain name
#'
#' @description Get Punycode for domain name.
#' @param domain domain name to get punycode for
#' @return Return the converted punycode of the domain
#' @import reticulate
#' @export
#' @examples \dontrun{
#' get_punycode("täst.de")
#' }
#'

get_punycode <- function(domain){
  ip2whois_init <- .getInit()
  result <- ip2whois_init$getPunycode(domain)
  return(reticulate::py_to_r(result))
}

#' @title Get Normat Text from a punycode
#'
#' @description Get Normat Text from a punycode for domain name.
#' @param domain The punycode domain name
#' @return Return normal domain name in text
#' @import reticulate
#' @export
#' @examples \dontrun{
#' get_normal_text("xn--tst-qla.de")
#' }
#'

get_normal_text <- function(domain){
  ip2whois_init <- .getInit()
  result <- ip2whois_init$getNormalText(domain)
  return(reticulate::py_to_r(result))
}

#' @title Get domain extension (gTLD or ccTLD) from URL or domain name
#'
#' @description Get domain extension from a URL or domain.
#' @param url The URL or domain.
#' @return Return normal domain name in text
#' @import reticulate
#' @export
#' @examples \dontrun{
#' get_domain_extension("example.com")
#' }
#'

get_domain_extension <- function(url){
  ip2whois_init <- .getInit()
  result <- ip2whois_init$getDomainExtension(url)
  return(reticulate::py_to_r(result))
}
