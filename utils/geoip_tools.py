import requests
import socket
import whois
import pycountry
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError

_forensic_executor = ThreadPoolExecutor(max_workers=3)

def get_geoip_info(ip_address):
    error_msg = 'Unknown error'
    try:
        response = requests.get(f'http://ip-api.com/json/{ip_address}', timeout=5)
        if response.status_code == 200:
            data = response.json()
            if data.get('status') == 'success':
                return {
                    'ip': ip_address,
                    'country': data.get('country', 'Unknown'),
                    'country_code': data.get('countryCode', 'Unknown'),
                    'region': data.get('regionName', 'Unknown'),
                    'city': data.get('city', 'Unknown'),
                    'isp': data.get('isp', 'Unknown'),
                    'org': data.get('org', 'Unknown'),
                    'lat': data.get('lat', 0),
                    'lon': data.get('lon', 0),
                    'timezone': data.get('timezone', 'Unknown')
                }
        error_msg = 'API returned unsuccessful status'
    except Exception as e:
        error_msg = str(e)
    
    return {
        'ip': ip_address,
        'country': 'Unknown',
        'country_code': 'Unknown',
        'region': 'Unknown',
        'city': 'Unknown',
        'isp': 'Unknown',
        'org': 'Unknown',
        'lat': 0,
        'lon': 0,
        'timezone': 'Unknown',
        'error': error_msg
    }

def get_whois_info(ip_address):
    def _do_whois_lookup():
        try:
            w = whois.whois(ip_address)
            return {
                'domain_name': w.domain_name if hasattr(w, 'domain_name') else 'N/A',
                'registrar': w.registrar if hasattr(w, 'registrar') else 'N/A',
                'creation_date': str(w.creation_date) if hasattr(w, 'creation_date') else 'N/A',
                'expiration_date': str(w.expiration_date) if hasattr(w, 'expiration_date') else 'N/A',
                'name_servers': ', '.join(w.name_servers) if hasattr(w, 'name_servers') and w.name_servers else 'N/A',
                'status': ', '.join(w.status) if hasattr(w, 'status') and isinstance(w.status, list) else str(w.status) if hasattr(w, 'status') else 'N/A',
                'emails': ', '.join(w.emails) if hasattr(w, 'emails') and w.emails else 'N/A',
                'org': w.org if hasattr(w, 'org') else 'N/A',
                'country': w.country if hasattr(w, 'country') else 'N/A'
            }
        except Exception as e:
            return {'error': f"WHOIS lookup failed: {str(e)}"}
    
    try:
        future = _forensic_executor.submit(_do_whois_lookup)
        return future.result(timeout=10)
    except FuturesTimeoutError:
        future.cancel()
        return {'error': "WHOIS lookup timed out after 10 seconds"}
    except Exception as e:
        return {'error': f"WHOIS lookup failed: {str(e)}"}

def reverse_dns_lookup(ip_address):
    def _do_reverse_lookup():
        try:
            hostname = socket.gethostbyaddr(ip_address)
            return {
                'ip': ip_address,
                'hostname': hostname[0],
                'aliases': ', '.join(hostname[1]) if hostname[1] else 'None',
                'success': True
            }
        except socket.herror:
            return {
                'ip': ip_address,
                'hostname': 'Not found',
                'aliases': 'None',
                'success': False,
                'error': 'No hostname associated with this IP'
            }
        except Exception as e:
            return {
                'ip': ip_address,
                'hostname': 'Error',
                'aliases': 'None',
                'success': False,
                'error': str(e)
            }
    
    try:
        future = _forensic_executor.submit(_do_reverse_lookup)
        return future.result(timeout=5)
    except FuturesTimeoutError:
        future.cancel()
        return {
            'ip': ip_address,
            'hostname': 'Timeout',
            'aliases': 'None',
            'success': False,
            'error': 'Reverse DNS lookup timed out after 5 seconds'
        }
    except Exception as e:
        return {
            'ip': ip_address,
            'hostname': 'Error',
            'aliases': 'None',
            'success': False,
            'error': str(e)
        }

def get_country_flag_emoji(country_code):
    try:
        if country_code and len(country_code) == 2:
            return ''.join(chr(ord(c) + 127397) for c in country_code.upper())
        return '🌍'
    except:
        return '🌍'
