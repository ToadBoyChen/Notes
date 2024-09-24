import logging
import scrapy
import re

class SpiderSpider(scrapy.Spider):
    name = "spider"
    allowed_domains = ["www.allizom.org"]
    start_urls = ["https://www.allizom.org/"]

    ignore_list = [
        r'facebook\.com',
        r'twitter\.com',
        r'youtube\.com',
        r'instagram\.com',
        r'\.pdf$',
        r'\.jpg$',
        r'\.jpeg$',
        r'\.png$',
        r'\.gif$',
        r'support\.mozilla\.org',
        r'addons\.mozilla\.org',
        r'release-notes',
        r'support',
    ]

    sensitive_keywords = [
        r'admin',
        r'dashboard',
        r'config',
        r'login',
        r'settings',
        r'account',
        r'user',
        r'control',
        r'management',
    ]

    visited_links = set()  # Track visited links

    custom_settings = {
        'DEPTH_LIMIT': 3,
        'DOWNLOAD_DELAY': 0,  # Adjust to avoid hitting rate limits
        'ROBOTSTXT_OBEY': False,  # Bypass robots.txt
    }

    def parse(self, response):
        if response.status != 200:
            logging.warning(f"Skipped {response.url} with status {response.status}")
            return

        # Check for sensitive keywords in the URL
        if any(re.search(keyword, response.url) for keyword in self.sensitive_keywords):
            logging.info(f"Found potentially sensitive page: {response.url}")
            yield {'potentially_sensitive_page': response.url}

        # Extract forms and input fields
        forms = response.css('form')
        for form in forms:
            action = form.css('::attr(action)').get()
            method = form.css('::attr(method)').get(default='GET')
            inputs = form.css('input::attr(name)').getall()
            logging.info(f"Found form: {action}, Method: {method}, Inputs: {inputs}")
            
            if action and ('login' in action or 'search' in action or 'submit' in action):
                yield {
                    'form_action': action,
                    'form_method': method,
                    'input_fields': inputs
                }

        # Check for potential injection points in URLs
        links = response.css('a::attr(href)').getall()
        for link in links:
            link = response.urljoin(link)  # Normalize link

            if '?' in link:  # Check if URL contains query parameters
                yield {'potential_injection_point': link}

            # Check for sensitive links
            if any(re.search(keyword, link) for keyword in self.sensitive_keywords):
                logging.info(f"Found sensitive page: {link}")
                yield {'sensitive_page': link}

            # Follow only internal links that haven't been visited yet
            if link.startswith('https://www.allizom.org') and link not in self.visited_links:
                self.visited_links.add(link)  # Mark this link as visited
                yield response.follow(link, self.parse)

        # Target XSS and client-side issues
        scripts = response.css('script::attr(src)').getall()
        for script in scripts:
            if script.endswith('.js'):
                logging.info(f"Found JavaScript file: {script}")
                yield {'javascript_file': script}
                if script not in self.visited_links:
                    self.visited_links.add(script)  # Mark this script as visited
                    yield response.follow(script, self.parse)

        # Target potential misconfigurations
        hidden_inputs = response.css('input[type="hidden"]::attr(value)').getall()
        logging.info(f"Found hidden inputs: {hidden_inputs}")
        for hidden in hidden_inputs:
            yield {'hidden_input': hidden}

        # Target session management issues
        cookies = response.headers.getlist('Set-Cookie')
        for cookie in cookies:
            if 'HttpOnly' not in cookie.decode() or 'Secure' not in cookie.decode():
                yield {'insecure_cookie': cookie.decode()}
