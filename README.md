# update-cloudflare-ip-lists

`update-cloudflare-ip-lists` downloads the Recorded Future IP Risk List & then appends the rows to a dictionary, which are then de-duplicated & written to a new CSV. From here, it is then used by `update_ioc_list.py` to append the IPs to a list in Cloudflare to be used by the WAF. In addition, `update_ioc_list.py` has a function to append IPs from a second IP list (e.g., Salt API Security Attackers) and append those IPs to a separate list in Cloudflare.

## References

[Cloudflare API Documentation](https://developers.cloudflare.com/api/)

[Recorded Future Risk List Documentation](https://support.recordedfuture.com/hc/en-us/articles/115000897248-Recorded-Future-Risk-Lists)
