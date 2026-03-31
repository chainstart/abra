# Report 19: Phase-2 Batch-1 Incident Shortlist

## Selection Rules

- Include only DeFi-labeled incidents (`is_defi=true`)
- Exclude operational families: `account_compromise, social_engineering, supply_chain`
- Minimum parsed loss threshold: `$100,000` (technical-signal rows can still be included)
- Family diversification cap: `3` rows per attack family

## Selected Incidents

| Rank | Date | Target | Family | Loss USD | Reference | Incident ID |
|---:|---|---|---|---:|---|---|
| 1 | 2023-03-13 | Euler Finance | flash_loan | 197,000,000.00 | https://twitter.com/SlowMist_Team/status/1635288963580825606 | `9c8e1b8431b3cb32761e7d0cabce8b29125d3bd4` |
| 2 | 2022-04-17 | Beanstalk | flash_loan | 182,000,000.00 | https://twitter.com/BlockSecTeam/status/1515683983836979201 | `98f36ce982afd6b00abb3fdc6ae7826e82b39b8c` |
| 3 | 2021-10-27 | Cream Finance | flash_loan | 130,000,000.00 | https://medium.com/cream-finance/post-mortem-exploit-oct-27-507b12bb6f8e | `b41b6e171b5a2508a775c8b379a9b9962831bdf3` |
| 4 | 2023-02-02 | BonqDAO & AllianceBlock | oracle_manipulation | 120,000,000.00 | https://www.theblock.co/post/207799/bonqdao-exploited-for-88-million-allianceblock-tokens-stolen-during-the-exploit | `7493b5601979d4b397c6a253dcaecdc0d294925f` |
| 5 | 2022-04-30 | Fei Protocol & Rari Capital | reentrancy | 80,000,000.00 | https://twitter.com/feiprotocol/status/1520344430242254849 | `046a16602f1f313ccd81ca63123fd96494d1bd5d` |
| 6 | 2021-05-13 | xToken | oracle_manipulation | 25,000,000.00 | https://twitter.com/FrankResearcher/status/1392515198674681863 | `6ba350af3e9c9de07f33739a00f0ae8419179344` |
| 7 | 2020-04-19 | Lendf.Me | reentrancy | 24,696,616.00 | https://www.zdnet.com/article/hackers-steal-25-million-worth-of-cryptocurrency-from-uniswap-and-lendf-me/ | `f61e140e3be3c74118c02cef25fb70c42021cf8c` |
| 8 | 2024-06-10 | UwU Lend | oracle_manipulation | 19,300,000.00 | https://x.com/SlowMist_Team/status/1800181916857155761 | `50dac4510849f4e918c65bce73352846cd9b6865` |
| 9 | 2021-05-14 | flash.sx | reentrancy | 11,742,000.00 | https://cmichel.io/eos-vault-sx-hack/ | `6f9a266f181fb0d04d15761a77b18f5972f704b7` |
| 10 | 2025-05-22 | Cetus | contract_bug | 230,000,000.00 | https://x.com/CetusProtocol/status/1925515662346404024 | `96e7b65db01b6b84d7209188ffa99057d1eaaff0` |
| 11 | 2025-11-03 | Balancer V2 | logic_bug | 121,100,000.00 | https://x.com/balancer/status/1990856260988670132 | `aa6d09e66fb71825b1beed519f0cc6a4956243fa` |
| 12 | 2022-05-28 | Mirror Protocol | contract_bug | 90,000,000.00 | https://twitter.com/FatManTerra/status/1529978941062139906 | `e5357c2516b32d38ba4b584fef37dd3820e0ece3` |

## Next Action

Run card generation for this shortlist and start Foundry fork replay implementation.
