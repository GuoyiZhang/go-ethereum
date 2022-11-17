./geth --datadir data init genesis.json

./geth --datadir data --networkid 1337 --http --http.addr 127.0.0.1 --http.port 8545 --http.api personal,eth,net,web3 --http.corsdomain '*' console 2>>geth.log &

./geth --datadir data --networkid 666 --http --http.addr 127.0.0.1 --http.port 8848 --http.api personal,eth,net,web3 --http.corsdomain '*' console 2>>geth.log &

> eth.accounts

> personal.newAccount();

> miner.start()

> eth.getBalance(eth.accounts[0])

> web3.fromWei(eth.getBalance(eth.accounts[0]))

> POST http://127.0.0.1:8545

{"id":"5","jsonrpc":"2.0","method":"eth_accounts", "params":[]}
