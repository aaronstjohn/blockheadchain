
from crypto import create_pubkey,sign,verify,crypto_hash,combine_hex

mint_passphrase = 'mo-money'
mint_pubkey = create_pubkey(mint_passphrase)

class Transaction(object):
    """
    Just a simple object to store our transaction data
    """
    def __init__(self,current_owner_pubkey,previous_owner_pubkey,transaction_signature,previous_transaction=None):
        self.current_owner_pubkey = current_owner_pubkey
        self.previous_owner_pubkey = previous_owner_pubkey
        self.transaction_signature = transaction_signature
        self.previous_transaction = previous_transaction
    
    def __repr__(self):
        return self.transaction_signature

def mint_coin(pubkey_owner):
    """
    Tells the mint to create a new coin and assign it to the public key of the new owner
    """
    return Transaction(current_owner_pubkey=pubkey_owner,
                        previous_owner_pubkey=mint_pubkey, 
                        transaction_signature=sign(crypto_hash(pubkey_owner),mint_passphrase))

def validate_transaction(tx):
    """
    Checks a single transaction to make sure its valid by making sure the transaction is a valid signature of the coin's previous owner
    """
    if tx.previous_transaction == None:
        #This is a special case representing transactions created by mint_coin that create the coin
        to_hash = tx.current_owner_pubkey
    else:
        to_hash = combine_hex(tx.previous_transaction.transaction_signature,tx.current_owner_pubkey)
    
    to_verify = crypto_hash(to_hash)
    return verify(to_verify,tx.transaction_signature,tx.previous_owner_pubkey)
 
def validate_coin(coin):
    """
    Validates a coin by going through all the transactions a coin has had on it to make sure the chain of ownership is valid for its entire history
    """
    n_transactions =0   
    while coin != None:
        n_transactions+=1
        if not validate_transaction(coin):
            print(f" Invalid coin on the {n_transactions} transaction")
            return False
        coin = coin.previous_transaction
    
    print(f"Validated coin after {n_transactions}")
    return True
    

def send(coin,pubkey_next_owner,current_owner_privkey):
    """
    Simulate the owner of the coin sending the coin to another user's public key by creating a valid signature for it
    """
    to_hash= combine_hex(coin.transaction_signature,pubkey_next_owner)
    
    to_sign = crypto_hash(to_hash)
    return Transaction(current_owner_pubkey=pubkey_next_owner,
                        previous_owner_pubkey=coin.current_owner_pubkey,
                        transaction_signature=sign(to_sign,current_owner_privkey),
                        previous_transaction = coin)
     

alice_pub = create_pubkey("Alice")
alice_coin = mint_coin(alice_pub)



print (f"created coin For alice {alice_coin}")
print (f"Coin is valid {validate_coin(alice_coin)}")

bob_pub = create_pubkey("Bob")
bob_coin = send(alice_coin,bob_pub,"Alice")

print (f"Alice sent coin to Bob: {bob_coin}")
print (f"Coin is valid {validate_coin(bob_coin)}")

eve_pub = create_pubkey("Eve")
eve_coin = send(alice_coin,eve_pub,"Alice")

print (f"Alice sent coin to Eve: {eve_coin}")
print (f"Coin is valid {validate_coin(eve_coin)}")