#!/usr/bin/env python3

import argparse
import json
import os
import re
import string
from lib.banner import WriteBanner
from urllib.parse import urlparse
from unicodedata import normalize

import requests
from bs4 import BeautifulSoup, SoupStrainer


class SourceMapExtractor(object):

    _target = None
    _is_local = False
    _attempt_sourcemap_detection = False
    _output_directory = ""
    _target_extracted_sourcemaps = []

    _path_sanitiser = None


    def __init__(self, options):
        if 'output_directory' not in options:
            raise SourceMapExtractorError("output_directory must be set in options.")
        else:
            self._output_directory = os.path.abspath(options['output_directory'])
            if not os.path.isdir(self._output_directory):
                if options['make_directory'] is True:
                    os.mkdir(self._output_directory)
                else:
                    raise SourceMapExtractorError("output_directory does not exist. Pass --make-directory to auto-make it.")

        self._path_sanitiser = PathSanitiser(self._output_directory)

        if options['disable_ssl_verification'] == True:
            self.disable_verify_ssl = True
        else:
            self.disable_verify_ssl = False
          
        if options['local'] == True:
            self._is_local = True

        if options['detect'] == True:
            self._attempt_sourcemap_detection = True

        self._validate_target(options['uri_or_file'])


    def run(self):
        if self._is_local == False:
            if self._attempt_sourcemap_detection:
                detected_sourcemaps = self._detect_js_sourcemaps(self._target)
                for sourcemap in detected_sourcemaps:
                    self._parse_remote_sourcemap(sourcemap)
            else:
                self._parse_remote_sourcemap(self._target)

        else:
            self._parse_sourcemap(self._target)


    def _validate_target(self, target):
        parsed = urlparse(target)
        if self._is_local is True:
            self._target = os.path.abspath(target)
            if not os.path.isfile(self._target):
                raise SourceMapExtractorError("uri_or_file is set to be a file, but doesn't seem to exist. check your path.")
        else:
            if parsed.scheme == "":
                raise SourceMapExtractorError("uri_or_file isn't a URI, and --local was not set. set --local?")
            file, ext = os.path.splitext(parsed.path)
            self._target = target
            if ext != '.map' and self._attempt_sourcemap_detection is False:
                print("WARNING: URI does not have .map extension, and --detect is not flagged.")


    def _parse_remote_sourcemap(self, uri):
        data, final_uri = self._get_remote_data(uri)
        if data is not None:
            self._parse_sourcemap(data, True)
        else:
            print("WARNING: Could not retrieve sourcemap from URI %s" % final_uri)


    def _detect_js_sourcemaps(self, uri):
        remote_sourcemaps = []
        data, final_uri = self._get_remote_data(uri)

        print("Detecting sourcemaps in HTML at %s" % final_uri)
        script_strainer = SoupStrainer("script", src=True)
        try:
            soup = BeautifulSoup(data, "html.parser", parse_only=script_strainer)
        except:
            raise SourceMapExtractorError("Could not parse HTML at URI %s" % final_uri)

        for script in soup:
            source = script['src']
            parsed_uri = urlparse(source)
            next_target_uri = ""
            if parsed_uri.scheme != '':
                next_target_uri = source
            else:
                current_uri = urlparse(final_uri)
                built_uri = current_uri.scheme + "://" + current_uri.netloc + source
                next_target_uri = built_uri

            js_data, last_target_uri = self._get_remote_data(next_target_uri)
        
            last_line = js_data.rstrip().split("\n")[-1]
            regex = r"\\/\\/#\s*sourceMappingURL=(.*)$"
            matches = re.search(regex, last_line)
            if matches:
                asset = matches.groups(0)[0].strip()
                asset_target = urlparse(asset)
                if asset_target.scheme != '':
                    print("Detected sourcemap at remote location %s" % asset)
                    remote_sourcemaps.append(asset)
                else:
                    current_uri = urlparse(last_target_uri)
                    asset_uri = current_uri.scheme + '://' + \
                        current_uri.netloc + \
                        os.path.dirname(current_uri.path) + \
                        '/' + asset
                    print("Detected sourcemap at remote location %s" % asset_uri)
                    remote_sourcemaps.append(asset_uri)

        return remote_sourcemaps


    def _parse_sourcemap(self, target, is_str=False):
        map_data = ""
        if is_str is False:
            if os.path.isfile(target):
                with open(target, 'r', encoding='utf-8', errors='ignore') as f:
                    map_data = f.read()
        else:
            map_data = target

        
        try:
            map_object = json.loads(map_data)
        except json.JSONDecodeError:
            print("ERROR: Failed to parse sourcemap %s. Are you sure this is a sourcemap?" % target)
            return False


        if 'sources' not in map_object or 'sourcesContent' not in map_object:
            print("ERROR: Sourcemap does not contain sources and/or sourcesContent, cannot extract.")
            return False

        if len(map_object['sources']) != len(map_object['sourcesContent']):
            print("WARNING: sources != sourcesContent, filenames may not match content")

        for source, content in zip(map_object['sources'], map_object['sourcesContent']):

            write_path = self._get_sanitised_file_path(source)
            if write_path is None:
                print("ERROR: Could not sanitize filename '%s'" % source)
                continue

            try:
                
                if not os.path.exists(os.path.dirname(write_path)):
                    os.makedirs(os.path.dirname(write_path))
                with open(write_path, 'w', encoding='utf-8', errors='ignore') as out_file:
                    out_file.write(content)
            except Exception as e:
                print("ERROR: Could not write file %s due to error: %s" % (write_path, e))
                continue

        return True


    def _get_remote_data(self, uri):
        
        if self.disable_verify_ssl:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        response = None
        try:
            response = requests.get(uri, verify=not self.disable_verify_ssl)
        except requests.exceptions.RequestException as e:
            print("ERROR: Unable to fetch data from %s due to error: %s" % (uri, e))
            return None, uri

        return response.text, uri


    def _get_sanitised_file_path(self, path):
        
        if self._path_sanitiser is None:
            return None
        sanitized = self._path_sanitiser.sanitize(path)
        return os.path.join(self._output_directory, sanitized)


class PathSanitiser(object):
    

    def __init__(self, output_directory):
        self.output_directory = output_directory
        self.disallowed = set(string.punctuation) - {'_', '-', '.', '/'}
        self.replacements = {' ': '_'}

    def sanitize(self, path):
        
        path = normalize('NFKD', path)
        sanitized_path = []
        for char in path:
            if char in self.disallowed:
                sanitized_path.append(self.replacements.get(char, '_'))
            else:
                sanitized_path.append(char)
        return ''.join(sanitized_path)


class SourceMapExtractorError(Exception):
    
    pass


if __name__ == '__main__':
    WriteBanner.banner()  
    parser = argparse.ArgumentParser(description="Extract uncompiled source code from Webpack source maps.")
    parser.add_argument("uri_or_file", help="The URI or local file path of the Webpack bundle or sourcemap.")
    parser.add_argument("-o", "--output-directory", default=".", help="Directory where the extracted sources will be saved.")
    parser.add_argument("-d", "--detect", action="store_true", help="Attempt to detect sourcemaps in JavaScript files.")
    parser.add_argument("--local", action="store_true", help="Treat the input as a local file.")
    parser.add_argument("--make-directory", action="store_true", help="Create the output directory if it does not exist.")
    parser.add_argument("--disable-ssl-verification", action="store_true", help="Disable SSL verification for remote requests.")

    args = parser.parse_args()

    options = {
        'uri_or_file': args.uri_or_file,
        'output_directory': args.output_directory,
        'detect': args.detect,
        'local': args.local,
        'make_directory': args.make_directory,
        'disable_ssl_verification': args.disable_ssl_verification,
    }

    extractor = SourceMapExtractor(options)
    extractor.run()