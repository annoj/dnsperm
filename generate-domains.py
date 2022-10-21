#!/usr/bin/env python3

import argparse
import dns.resolver
from dnstwist import Fuzzer, UrlParser
from tqdm import tqdm
import multiprocessing
from multiprocessing import Pool, freeze_support

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--domain-list',
            help='Textfile containing domains, one per line',
            required=True)
    parser.add_argument('-o', '--output-dir',
            help='Results are written here', required=True)
    return parser.parse_args()

def check_domain_has_mx_entry(domain):
    try:
        dns.resolver.resolve(domain, 'MX')
        return True
    except:
        return False

def generate_permutations_and_write_to_file(domain, output_dir):
    try:
        url = UrlParser(domain)
    except ValueError:
        return f'{domain} is not a valid URL.'

    if not check_domain_has_mx_entry(domain):
        return f'{domain} has no MX record'

    fuzz = Fuzzer(url.domain)
    fuzz.generate()
    domains = fuzz.domains

    with open(f'{output_dir}/{domain}.csv', 'w') as f:
        f.writelines(map(
                lambda d: f"{domain},{d['domain']}\n",
                filter(lambda d: d != domain, domains)))

def main():
    args = parse_args()

    with open(args.domain_list) as f:
        domains = [d.strip() for d in f.readlines()]
    
    with Pool(processes=multiprocessing.cpu_count()) as pool:
        jobs = [pool.apply_async(
                    func=generate_permutations_and_write_to_file,
                    args=(domain, args.output_dir))
                for domain in domains]

        result_list = [job.get() for job in tqdm(jobs)]

    with open(f'{args.output_dir}/failed_domains.txt', 'w') as f:
        f.writelines([f'{r}\n' for r in result_list if r is not None])

if __name__ == '__main__':
    # Enable multiprocessing on Mac and Windows where new processes are
    # not fork'd
    freeze_support() 
    main()

