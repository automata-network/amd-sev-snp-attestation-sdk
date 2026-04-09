package bindings

//go:generate sh -c "python3 -c \"import json,sys; f=open(sys.argv[1]); d=json.load(f); json.dump(d['abi'],open(sys.argv[2],'w'))\" ../../../../contracts/out/SEVAgentAttestation.sol/SEVAgentAttestation.json /tmp/sev_abi.json && abigen --abi /tmp/sev_abi.json --pkg bindings --type SEVAgentAttestation --out sev_agent_attestation.go"
