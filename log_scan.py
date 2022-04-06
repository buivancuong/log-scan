import re
import sys
from os import walk

global global_rules
global_rules = {"rx":{}, "pm":{}}
rx_pattern = '\\"@rx\\s(.*)\\"\\s\\\\'
pm_pattern = '\\"@pm\\s(.*)\\"\\s\\\\'


def load_ModSecurity_rule_from_directory(rule_dir):
    global global_rules
    filenames = next(walk(rule_dir), (None, None, []))[2]  # [] if no file
    # print(filenames)
    for file in filenames:
        for rule_type in global_rules:
            if file not in global_rules[rule_type]:
                global_rules[rule_type][file] = list()
        file_path = rule_dir + file
        with open(file_path) as rule_file:
            for line in rule_file:
                if not line: continue
                if line[0] == '#': continue
                if line[0:7] != 'SecRule': continue
                rx_match = re.search(rx_pattern, line)
                if rx_match:
                    global_rules['rx'][file].append(rx_match.group(1))
                    continue
                pm_match = re.search(pm_pattern, line)
                if pm_match:
                    matches = pm_match.group(1).split()
                    for word in matches: global_rules['pm'][file].append(word)
                    continue


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Syntax: %s <log_file_path>" %sys.argv[0])
        sys.exit()
    log_file_path = sys.argv[1]

    with open(log_file_path) as log_file:
        logs = [line.rstrip('\n') for line in log_file]

    load_ModSecurity_rule_from_directory('rule/modsecurity/')
    
    for line in logs:
        if not line: continue
        url_pattern = '\"[A-Z]+\s(\/\S+)'
        url_match = re.search(url_pattern, line)
        if not url_match: continue
        url = url_match.group(1)
        for rule_type in global_rules:
            if rule_type == 'rx':
                for rule_file in global_rules[rule_type]:
                    for rule in global_rules[rule_type][rule_file]:
                        try: 
                            if not re.search(rule, url): continue
                        except: continue
                        # print("RULE REGEX: " + rule)
                        print("url: " + url)
                        print("LOG: " + line)
                        print("ALERT: " + rule_file)
                        print()
            elif rule_type == 'pm':
                for rule_file in global_rules[rule_type]:
                    for rule in global_rules[rule_type][rule_file]:
                        try:
                            rule_regex = re.compile(rule)
                            if not rule_regex.search(url): continue
                        except: continue
                        # print("RULE MATCH: " + rule)
                        print("url: " + url)
                        print("LOG: " + line)
                        print("ALERT: " + rule_file)
                        print()

    