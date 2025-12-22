// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "./RiscZeroGroth16Setup.sol";
import "./SuccinctGroth16Setup.sol";
import "./PicoGroth16Setup.sol";
import "../src/SEVAgentAttestation.sol";
import "../src/types/SevSnpTypes.sol";
import "../src/interfaces/ISnpAttestation.sol";

contract SEVAgentTest is RiscZeroGroth16Setup, SuccinctGroth16Setup, PicoGroth16Setup {
    address internal constant admin = address(1);
    string internal picoInputJson = vm.readFile(string.concat(vm.projectRoot(), "/test/assets/pico-inputs.json"));
    string internal riscZeroJson = vm.readFile(string.concat(vm.projectRoot(), "/test/assets/boundless_azure.json"));
    string internal sp1Json = vm.readFile(string.concat(vm.projectRoot(), "/test/assets/sp1_gcp.json"));

    bytes constant ARK_MILAN_DER =
        hex"3082066330820412a0030201020203010000304606092a864886f70d01010a3039a00f300d06096086480165030402020500a11c301a06092a864886f70d010108300d06096086480165030402020500a203020130a303020101307b31143012060355040b0c0b456e67696e656572696e67310b30090603550406130255533114301206035504070c0b53616e746120436c617261310b300906035504080c024341311f301d060355040a0c16416476616e636564204d6963726f20446576696365733112301006035504030c0941524b2d4d696c616e301e170d3230313032323137323330355a170d3435313032323137323330355a307b31143012060355040b0c0b456e67696e656572696e67310b30090603550406130255533114301206035504070c0b53616e746120436c617261310b300906035504080c024341311f301d060355040a0c16416476616e636564204d6963726f20446576696365733112301006035504030c0941524b2d4d696c616e30820222300d06092a864886f70d01010105000382020f003082020a0282020100d0b779d9124e75e88996a2b625db15983ec592dba8b56c17d5f3605b8d5763d5f3d471214949a12f3f42bbd0c7465be02523716de618b2725fbf28f1d4c7d4d15e6d90a894d447ac345b5ad644c0d2cccd8ac75873d8acaa4ee65d3e7e29f1916df73857ff73448704f2394737ad52d63bbc5fddfee9dc4352b1b64b3c6a278061ab2626503aee3d72525f8bd4734d4fee3f7c329a8e4bde6b3917461de239d8d6b3e66d81f8efaf8ec0b4eb4777ee363d2c57ae38fe0c7ab8bcaa07e2d92e642aa83f685e9a3edb80650551eeedca1585cfe7d5e6260b5ca20d398262344ff3a2b4b86ecd5be965c2e9874a1d87fd483d7ab1dfe3278c3f7b03b7d7a6a19dff2f0ac57ee392c4c4cc03a06ca01e6a6de59bedf228871360c96c44c5cf72335b22f9ac072903fffc529e2bacb870648279443445b1d5471b410aecfa054392e54f86c9f321136062f338f18fbb2c6889627ae613cc5cadec5e901c6bbdad95f53250aa7377439de4b79be2422dfe8027e69300b4174b62ac865b2e45cfacfc3367433d78dc6123249bda7a497e09eacf9e48d2edf7c21e2bd1935079319fc34dcc054b72bb319eb0691cc3e968a8c6aad6a478b6319b3d8c42be90aaefe3a0a420a830d8addae2e8f4cd7c7c7cf5d2538c4fc9d6014bd1645ced7970a6fbb3c77583e5990c14c372ef7a727f20b5e840f1df6e41f40b23df865d635a124565ab0203010001a37e307c300e0603551d0f0101ff040403020106301d0603551d0e0416041485ac1ad143f7c8ac55d4c51d4148abd5784ad453300f0603551d130101ff040530030101ff303a0603551d1f04333031302fa02da02b862968747470733a2f2f6b6473696e74662e616d642e636f6d2f7663656b2f76312f4d696c616e2f63726c304606092a864886f70d01010a3039a00f300d06096086480165030402020500a11c301a06092a864886f70d010108300d06096086480165030402020500a203020130a3030201010382020100ba9b4903a7acefe0e8df832fb395e7a1b31ea8974a1c8157a5113a1ba71f84b82b2a54544f2b58d9d6ca7f97277dfb47d0d2beba9fb91a81193809adfd83ae9619324c78976a62b8b04938e30c22953d27ac59760f540c838663f99f6bfe0588a9656869beaa5a88ef8418ae4804ffb9efc41e5bfb12a24aca74768b0311b62e16718fd685ef77ea0bb380259e5a3e89f0e11136f7d1556ab8754f1d9e4f7c128240e0bad09307562acd3e43bb0bc07be728d822152333036a662e4858cf3740428288e5ed5f9b4e8bbb74cb2a22efd35bfacf097f7f1147292862aa3d0dcff8df6bd618c4158d6994183ddede7738ea38f46348f95d73bd73cb23ac48155b21fa6b68d91b60117fdea6630a4cd37aa6c5bcf2a83b7358535ad37a31b46e434be6f8efbfdad28117687c4c76fde0ebef1c7a050e96c210b96a1e7218871cb460a5c6c9a5b53637d42f1aeb9b1556e30727e44f0675d9af35aeb2626f2c7096a0122d779a11aee09aa1dd0537b1ff2251252bd3dc500f01ed39051522ac7899a0593c1b5231ffaa503b635d24aaf257d671df1b2ebf6676c527259274fadb8f30a9819d21fceb49652a4f95a5542c82a6f30c8bce2ef0fa5b5526ab6e5ba3109827e4ee0686b8b3e1c7095880be04fd91ffeb06ad5dfa2be3eac9241f1bb37316e4d71bfa646c6bb5e271547eca957ed845d67a78044ac0b7b8005644030a0a09";
    bytes constant ASK_MILAN_VCEK_DER =
        hex"3082068930820438a0030201020203010001304606092a864886f70d01010a3039a00f300d06096086480165030402020500a11c301a06092a864886f70d010108300d06096086480165030402020500a203020130a303020101307b31143012060355040b0c0b456e67696e656572696e67310b30090603550406130255533114301206035504070c0b53616e746120436c617261310b300906035504080c024341311f301d060355040a0c16416476616e636564204d6963726f20446576696365733112301006035504030c0941524b2d4d696c616e301e170d3230313032323138323432305a170d3435313032323138323432305a307b31143012060355040b0c0b456e67696e656572696e67310b30090603550406130255533114301206035504070c0b53616e746120436c617261310b300906035504080c024341311f301d060355040a0c16416476616e636564204d6963726f20446576696365733112301006035504030c095345562d4d696c616e30820222300d06092a864886f70d01010105000382020f003082020a02820201009d4d9daeb3537db84d4089657fe5b6cbe44e09b4b321dd5a2997edd93f738d940ece319c725d7b8b598829697b353701d15617b77271652cce663b232cd54010dd8c1a3f5389e74bf907b02995f4266404b988e6f962a4b0bb7181d2e9f44ec464dc0d0ea575af4a913f9b41f0e5a4c906c874b7aee1a0b3ee3fd2975164072b5ebfdb1b146cededcc278f38bd9bb9e8aac93eb91541a77f889f7e503dd723f187e51269c704dbee5032612c224c5bc28e8cfebef8f85bb378828ad25c00d12d5b8a93345a0a5b708795b7120a34ccf0ab0d6d4c7703c7a4e4454b8d9587d69b7d1374dfa51e97c9f40a9d8ea497968420fc1d5b778561aa8214fac8a3da504fa5ae0d23f82426096d99de28a21b663cd7909b773501b7d84ba46089816fd482926f7e7d2e4b64583da23cee6cc5f7f8d901a125c8ece3ef9c73318eea7d9b0e6c7ba41457b1aaa420364cdca9a259ae43e7006b157b26a1c4f1d97da567fe6376ab6fef628850b016de25025270e43d024d14c2d58e585850c10ab03fbc69e64e7a86f02fa38d4012edc8e347cab838f8720e62513e7682fd91b9b8fd0ad33e86a0eff7b9e9fdc2ab210ae1de80b4e939e1c42512ab405af83d523054e074f9e6cee45828c8ec38de7c850f950a043c4407804aa3fd2e0222872d1bef80b6ce45b53c280448b35128a848e617c52dae64165768548f0ceac2f1c57a2f2b3f130203010001a381a33081a0301d0603551d0e041604143bc66e182ac3fd3d6264489be3b7472cb4fcbff8301f0603551d2304183016801485ac1ad143f7c8ac55d4c51d4148abd5784ad45330120603551d130101ff040830060101ff020100300e0603551d0f0101ff040403020104303a0603551d1f04333031302fa02da02b862968747470733a2f2f6b6473696e74662e616d642e636f6d2f7663656b2f76312f4d696c616e2f63726c304606092a864886f70d01010a3039a00f300d06096086480165030402020500a11c301a06092a864886f70d010108300d06096086480165030402020500a203020130a3030201010382020100881e51049c01fde50d8aa0594d55b650db98837c4b6742e64990cec67f1ed0234272c43c8d638778096cbc4bea07f72bc8f172dcce5a791871b75f30e3abdbc293df921a011db4ade90a445a6d4c785ef8316bdc017364b0c3edc58adbdfc6a4f8ad3c90ca0af23b038520d3aae4ec9d3305ed5fcffa9ee22dbf175dabbdfc0219885c4713f2ed0177abc7d1e86089741d544394a5c028c5c43e2e7b3511ced2252008cc92dec316f29187edb32bee6995518616c8c326d333dae77dcb4a6f384e23ddd1f9216f631b1692192b6a36b69b9e7a45db7e844ebd7f6b8ddbf0514a2f940d9adf15afdc675d1a739ea091bea8ebfa456b6fa7657ee4e59625de4133250684561493912fc01c049c466782b69977ed9758d4e532de8792972fd356edafea00e214b361623a1aabb7302125183d223f10910f4f93e70a1b3c3a125dd3de416b120eb39319af32e69b64eb1d29f46459f847d9929c4e50df987d47d33ab44366c6deebda55d882b456352e55b2077f094b67cdb11fcfcbab796eb10908536fcda0e4cba29e0b88a89ff7158146a2ef3cd2ddb1905b3283294df94aa354d9690f23cc42674d16b4888a2859d7594431be52a69a06412183ded35cc3d0df1ab45c665a24a77c997af7407dac9a4d47f7c86a3c425b749e8b0b3aaf5666fad0ae55b32236da52f53863357e2ebdee6d8727c4d83828c5116f6350aca05e4c";
    bytes32 SEV_IMAGE_RISCZERO_ID = vm.envBytes32("SEV_AGENT_RISCZERO_IMAGE_ID");
    bytes32 SEV_AGENT_SP1_VKEY = vm.envBytes32("SEV_AGENT_SP1_VKEY");

    SEVAgentAttestation attestation;

    function setUp() public override {
        super.setUp();

        vm.startPrank(admin);

        bytes32[] memory initialTrustedCerts = new bytes32[](1);
        initialTrustedCerts[0] = 0x3dc78a6a9573a5e45d266144a86f05ef45829da59ff7f5552e066a67026a5ad8;
        attestation = new SEVAgentAttestation(admin, 100000, initialTrustedCerts);

        bytes memory ark = vm.readFileBinary(string.concat(vm.projectRoot(), "/test/assets/ark-milan.der"));
        attestation.setRootCert(ProcessorType.Milan, sha256(ark));

        ZkCoProcessorConfig memory riscZeroConfig = ZkCoProcessorConfig({
            latestProgramIdentifier: SEV_IMAGE_RISCZERO_ID, defaultZkVerifier: address(riscZeroVerifier)
        });
        SEVAgentAttestation(attestation).setZkConfiguration(ZkCoProcessorType.RiscZero, riscZeroConfig);

        address sp1Verifier = setupSp1();
        ZkCoProcessorConfig memory sp1Config =
            ZkCoProcessorConfig({latestProgramIdentifier: SEV_AGENT_SP1_VKEY, defaultZkVerifier: sp1Verifier});
        SEVAgentAttestation(attestation).setZkConfiguration(ZkCoProcessorType.Succinct, sp1Config);

        address picoVerifier = setupPico();
        bytes32 sevPicoVkey = abi.decode(vm.parseJson(picoInputJson, ".riscvVKey"), (bytes32));
        ZkCoProcessorConfig memory picoConfig =
            ZkCoProcessorConfig({latestProgramIdentifier: sevPicoVkey, defaultZkVerifier: picoVerifier});
        SEVAgentAttestation(attestation).setZkConfiguration(ZkCoProcessorType.Pico, picoConfig);

        vm.stopPrank();
    }

    function testSevAttestationRiscZero() public {
        // prevents InvalidTimestamp error
        vm.warp(1766025108);

        bytes memory riscZeroOutput = abi.decode(vm.parseJson(riscZeroJson, ".raw_proof.journal"), (bytes));
        bytes memory riscZeroProof = abi.decode(vm.parseJson(riscZeroJson, ".onchain_proof"), (bytes));
        VerifierJournal memory riscZeroZkOutput =
            attestation.verifyAndAttestWithZKProof(riscZeroOutput, ZkCoProcessorType.RiscZero, riscZeroProof);

        assertEq(uint8(riscZeroZkOutput.result), uint8(VerificationResult.Success));
        assertEq(riscZeroZkOutput.processorModel, uint8(ProcessorType.Milan));
    }

    function testSevAttestationSuccinct() public {
        // prevents InvalidTimestamp error
        vm.warp(1766026012);

        bytes memory programOutput = abi.decode(vm.parseJson(sp1Json, ".raw_proof.journal"), (bytes));
        bytes memory proof = abi.decode(vm.parseJson(sp1Json, ".onchain_proof"), (bytes));

        VerifierJournal memory zkOutput =
            attestation.verifyAndAttestWithZKProof(programOutput, ZkCoProcessorType.Succinct, proof);

        assertEq(uint8(zkOutput.result), uint8(VerificationResult.Success));
        assertEq(zkOutput.processorModel, uint8(ProcessorType.Milan));
    }

    function testSevAttestationPico() public {
        // prevents InvalidTimestamp error
        vm.warp(1761733828);

        bytes memory publicValues = abi.decode(vm.parseJson(picoInputJson, ".publicValues"), (bytes));
        bytes32[] memory proofBytes32 = abi.decode(vm.parseJson(picoInputJson, ".proof"), (bytes32[]));

        uint256[8] memory proofArray;
        for (uint256 i = 0; i < 8; i++) {
            proofArray[i] = uint256(proofBytes32[i]);
        }

        VerifierJournal memory journal =
            attestation.verifyAndAttestWithZKProof(publicValues, ZkCoProcessorType.Pico, abi.encode(proofArray));

        assertEq(uint8(journal.result), uint8(VerificationResult.Success));
    }
}
