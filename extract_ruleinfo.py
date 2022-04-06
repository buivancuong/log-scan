import re
import os
from os import walk
import json

global global_rules
global_rules = {"rx":{}, "pm":{}}       # {"rx": {"rule_file": [("arg","pcre","msg")]}, "pm": {"rule_file": [("arg","match","msg")]}}
# rx_pattern = '\\"@rx\\s(.*)\\"\\s\\\\'
rx_pattern = '\"@rx\s(.*)\"\s'
# pm_pattern = '\\"@pm\\s(.*)\\"\\s\\\\'
pm_pattern = '\"@pm\s(.*)\"\s'
rule_pattern = 'SecRule\s(.*)\s\"@[rp][xm]\s.*\"id:(\d+),.*,msg:\'(.*)\',severity'
# pattern_dict  = {
#     'rx': '\\"@rx\\s(.*)\\"\\s\\\\',
#     'pm': '\\"@pm\\s(.*)\\"\\s\\\\'
# }

def load_ModSecurity_rule_from_dir(rule_dir):
    global global_rules
    # filenames = next(walk(rule_dir), (None, None, []))[2]  # [] if no file
    filenames = list()
    for path, subdirs, filepaths in os.walk(rule_dir):
        for file in filepaths: filenames.append(os.path.join(path, file))

    for file in filenames:
        for rule_type in global_rules:
            if file not in global_rules[rule_type]: global_rules[rule_type][file] = list()
        with open(file) as rule_file: rules = rule_file.read().splitlines()
        # if 'XSS' in file:
        #     for rule in rules: print(rule)
        for i in range(len(rules)):
            if not len(rules[i]): continue
            if '#' in rules[i][0]: continue
            if rules[i][0:7] != 'SecRule': continue
            if 'nolog' in rules[i]: continue
            if i > 0 and len(rules[i - 1]): continue
            rx_match = re.search(rx_pattern, rules[i])
            if rx_match:
                rule_match = re.search(rule_pattern, rules[i])
                if not rule_match: continue
                arg = rule_match.group(1)
                id = rule_match.group(2)
                msg = rule_match.group(3)
                rule_tuple = (id, arg, rx_match.group(1), msg)
                if file in global_rules['rx']: global_rules['rx'][file].append(rule_tuple)
                else: global_rules['rx'][file] = [rule_tuple]
                continue
            pm_match = re.search(pm_pattern, rules[i])
            if pm_match:
                matches = pm_match.group(1).split()
                rule_match = re.search(rule_pattern, rules[i])
                if not rule_match: continue
                arg = rule_match.group(1)
                id = rule_match.group(2)
                msg = rule_match.group(3)
                for word in matches:
                    rule_tuple = (id, arg, word, msg)
                    if file in global_rules['pm']: global_rules['pm'][file].append(rule_tuple)
                    else: global_rules['pm'][file] = [rule_tuple]
                continue


if __name__ == '__main__':
    load_ModSecurity_rule_from_dir('rule/modsecurity/')
    # print(global_rules)
    with open('result.json', 'w') as f: json.dump(global_rules, f)