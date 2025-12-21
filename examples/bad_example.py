# Bad Example for Testing CodeRabbit
from hiero_sdk_python import Client, AccountCreateTransaction

# MISTAKE: No main block or env setup
client = Client.for_testnet() 

# MISTAKE: Bad naming
my_acc = client.operator_account_id 

# MISTAKE: Missing freeze_with before sign (if needed) and no response check
tx = AccountCreateTransaction()
tx.set_key(client.operator_public_key)
tx.set_initial_balance(0)

# MISTAKE: Just executing without checking receipt
tx.execute(client)