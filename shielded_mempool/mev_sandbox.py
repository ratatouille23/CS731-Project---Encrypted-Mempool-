"""A deterministic, synthetic x*y=k constant-product DEX sandwich illustration.

This is NOT a live MEV bot and uses no chain connectivity, real assets or
historical financial-loss estimation. It demonstrates the economic motivation
for concealing pending swap direction/size before a block's order is fixed.
"""
from __future__ import annotations
from dataclasses import dataclass

@dataclass
class AMM:
    token:float=1000.0
    quote:float=1_000_000.0
    fee:float=0.003

    def buy_token(self,quote_in:float)->float:
        if quote_in<=0:raise ValueError('amount must be positive')
        effective=quote_in*(1-self.fee)
        acquired=self.token*effective/(self.quote+effective)
        self.token-=acquired
        self.quote+=quote_in
        return acquired

    def sell_token(self,token_in:float)->float:
        if token_in<=0:raise ValueError('amount must be positive')
        effective=token_in*(1-self.fee)
        recovered=self.quote*effective/(self.token+effective)
        self.token+=token_in
        self.quote-=recovered
        return recovered


def sandwich_demo(victim_quote:float=50_000.,bot_quote:float=10_000.)->dict:
    clean=AMM(); expected_tokens=clean.buy_token(victim_quote)
    attacked=AMM()
    bot_token=attacked.buy_token(bot_quote)
    victim_tokens=attacked.buy_token(victim_quote)
    bot_exit=attacked.sell_token(bot_token)
    bot_profit=bot_exit-bot_quote
    loss=expected_tokens-victim_tokens
    # This is a conditional strategy assuming the adversary saw victim's order.
    return {'scenario':'simulated constant-product DEX, not historical loss data',
            'victim_quote_in':victim_quote,'attacker_quote_in':bot_quote,
            'victim_tokens_without_sandwich':expected_tokens,
            'victim_tokens_with_sandwich':victim_tokens,
            'victim_tokens_lost':loss,
            'bot_quote_profit_before_gas':bot_profit,
            'privacy_mechanism':'Encrypting victim payload until ordering prevents the bot from conditioning this attack on the unseen trade (under assumptions).',
            'limitations':'Does not prevent every MEV strategy, collusion or leak from public metadata.'}
