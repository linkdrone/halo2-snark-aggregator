// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.4.16 <0.9.0;

contract Verifier {
    function pairing(G1Point[] memory p1, G2Point[] memory p2)
        internal
        view
        returns (bool)
    {
        uint256 length = p1.length * 6;
        uint256[] memory input = new uint256[](length);
        uint256[1] memory result;
        bool ret;

        require(p1.length == p2.length);

        for (uint256 i = 0; i < p1.length; i++) {
            input[0 + i * 6] = p1[i].x;
            input[1 + i * 6] = p1[i].y;
            input[2 + i * 6] = p2[i].x[0];
            input[3 + i * 6] = p2[i].x[1];
            input[4 + i * 6] = p2[i].y[0];
            input[5 + i * 6] = p2[i].y[1];
        }

        assembly {
            ret := staticcall(
                gas(),
                8,
                add(input, 0x20),
                mul(length, 0x20),
                result,
                0x20
            )
        }
        require(ret);
        return result[0] != 0;
    }

    uint256 constant q_mod =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    function fr_invert(uint256 a) internal view returns (uint256) {
        return fr_pow(a, q_mod - 2);
    }

    function fr_pow(uint256 a, uint256 power) internal view returns (uint256) {
        uint256[6] memory input;
        uint256[1] memory result;
        bool ret;

        input[0] = 32;
        input[1] = 32;
        input[2] = 32;
        input[3] = a;
        input[4] = power;
        input[5] = q_mod;

        assembly {
            ret := staticcall(gas(), 0x05, input, 0xc0, result, 0x20)
        }
        require(ret);

        return result[0];
    }

    function fr_div(uint256 a, uint256 b) internal view returns (uint256) {
        require(b != 0);
        return mulmod(a, fr_invert(b), q_mod);
    }

    function fr_mul_add(
        uint256 a,
        uint256 b,
        uint256 c
    ) internal pure returns (uint256) {
        return addmod(mulmod(a, b, q_mod), c, q_mod);
    }

    function fr_mul_add_pm(
        uint256[84] memory m,
        uint256[] calldata proof,
        uint256 opcode,
        uint256 t
    ) internal pure returns (uint256) {
        for (uint256 i = 0; i < 32; i += 2) {
            uint256 a = opcode & 0xff;
            if (a != 0xff) {
                opcode >>= 8;
                uint256 b = opcode & 0xff;
                opcode >>= 8;
                t = addmod(mulmod(proof[a], m[b], q_mod), t, q_mod);
            } else {
                break;
            }
        }

        return t;
    }

    function fr_mul_add_mt(
        uint256[84] memory m,
        uint256 base,
        uint256 opcode,
        uint256 t
    ) internal pure returns (uint256) {
        for (uint256 i = 0; i < 32; i += 1) {
            uint256 a = opcode & 0xff;
            if (a != 0xff) {
                opcode >>= 8;
                t = addmod(mulmod(base, t, q_mod), m[a], q_mod);
            } else {
                break;
            }
        }

        return t;
    }

    function fr_reverse(uint256 input) internal pure returns (uint256 v) {
        v = input;

        // swap bytes
        v = ((v & 0xFF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00) >> 8) |
            ((v & 0x00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF) << 8);

        // swap 2-byte long pairs
        v = ((v & 0xFFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000) >> 16) |
            ((v & 0x0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF) << 16);

        // swap 4-byte long pairs
        v = ((v & 0xFFFFFFFF00000000FFFFFFFF00000000FFFFFFFF00000000FFFFFFFF00000000) >> 32) |
            ((v & 0x00000000FFFFFFFF00000000FFFFFFFF00000000FFFFFFFF00000000FFFFFFFF) << 32);

        // swap 8-byte long pairs
        v = ((v & 0xFFFFFFFFFFFFFFFF0000000000000000FFFFFFFFFFFFFFFF0000000000000000) >> 64) |
            ((v & 0x0000000000000000FFFFFFFFFFFFFFFF0000000000000000FFFFFFFFFFFFFFFF) << 64);

        // swap 16-byte long pairs
        v = (v >> 128) | (v << 128);
    }

    uint256 constant p_mod =
        21888242871839275222246405745257275088696311157297823662689037894645226208583;

    struct G1Point {
        uint256 x;
        uint256 y;
    }

    struct G2Point {
        uint256[2] x;
        uint256[2] y;
    }

    function ecc_from(uint256 x, uint256 y)
        internal
        pure
        returns (G1Point memory r)
    {
        r.x = x;
        r.y = y;
    }

    function ecc_add(uint256 ax, uint256 ay, uint256 bx, uint256 by)
        internal
        view
        returns (uint256, uint256)
    {
        bool ret = false;
        G1Point memory r;
        uint256[4] memory input_points;

        input_points[0] = ax;
        input_points[1] = ay;
        input_points[2] = bx;
        input_points[3] = by;

        assembly {
            ret := staticcall(gas(), 6, input_points, 0x80, r, 0x40)
        }
        require(ret);

        return (r.x, r.y);
    }

    function ecc_sub(uint256 ax, uint256 ay, uint256 bx, uint256 by)
        internal
        view
        returns (uint256, uint256)
    {
        return ecc_add(ax, ay, bx, p_mod - by);
    }

    function ecc_mul(uint256 px, uint256 py, uint256 s)
        internal
        view
        returns (uint256, uint256)
    {
        uint256[3] memory input;
        bool ret = false;
        G1Point memory r;

        input[0] = px;
        input[1] = py;
        input[2] = s;

        assembly {
            ret := staticcall(gas(), 7, input, 0x60, r, 0x40)
        }
        require(ret);

        return (r.x, r.y);
    }

    function _ecc_mul_add(uint256[5] memory input)
        internal
        view
    {
        bool ret = false;

        assembly {
            ret := staticcall(gas(), 7, input, 0x60, add(input, 0x20), 0x40)
        }
        require(ret);

        assembly {
            ret := staticcall(gas(), 6, add(input, 0x20), 0x80, add(input, 0x60), 0x40)
        }
        require(ret);
    }

    function ecc_mul_add(uint256 px, uint256 py, uint256 s, uint256 qx, uint256 qy)
        internal
        view
        returns (uint256, uint256)
    {
        uint256[5] memory input;
        input[0] = px;
        input[1] = py;
        input[2] = s;
        input[3] = qx;
        input[4] = qy;

        _ecc_mul_add(input);

        return (input[3], input[4]);
    }
    
    function ecc_mul_add_pm(
        uint256[84] memory m,
        uint256[] calldata proof,
        uint256 opcode,
        uint256 t0,
        uint256 t1
    ) internal view returns (uint256, uint256) {
        uint256[5] memory input;
        input[3] = t0;
        input[4] = t1;
        for (uint256 i = 0; i < 32; i += 2) {
            uint256 a = opcode & 0xff;
            if (a != 0xff) {
                opcode >>= 8;
                uint256 b = opcode & 0xff;
                opcode >>= 8;
                input[0] = proof[a];
                input[1] = proof[a + 1];
                input[2] = m[b];
                _ecc_mul_add(input);
            } else {
                break;
            }
        }

        return (input[3], input[4]);
    }

    function update_hash_scalar(uint256 v, uint256[144] memory absorbing, uint256 pos) internal pure {
        absorbing[pos++] = 0x02;
        absorbing[pos++] = v;
    }

    function update_hash_point(uint256 x, uint256 y, uint256[144] memory absorbing, uint256 pos) internal pure {
        absorbing[pos++] = 0x01;
        absorbing[pos++] = x;
        absorbing[pos++] = y;
    }

    function to_scalar(bytes32 r) private pure returns (uint256 v) {
        uint256 tmp = uint256(r);
        tmp = fr_reverse(tmp);
        v = tmp % 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001;
    }

    function hash(uint256[144] memory absorbing, uint256 length) private view returns (bytes32[1] memory v) {
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 2, absorbing, length, v, 32)
            switch success case 0 { invalid() }
        }
        assert(success);
    }

    function squeeze_challenge(uint256[144] memory absorbing, uint32 length) internal view returns (uint256 v) {
        absorbing[length] = 0;
        bytes32 res = hash(absorbing, length * 32 + 1)[0];
        v = to_scalar(res);
        absorbing[0] = uint256(res);
        length = 1;
    }

    function get_verify_circuit_g2_s() internal pure returns (G2Point memory s) {
        s.x[0] = uint256(7337269220088280927620402068691938429748050337547090773197167033919349445188);
        s.x[1] = uint256(3770121637545959242509070664098694248699786701464310021860735530167404521320);
        s.y[0] = uint256(10343964991691947571037409447120789505361606418249328495172646462999191672139);
        s.y[1] = uint256(17317880176565749919367963757539077029030327420388252207598334502905927580360);
    }

    function get_verify_circuit_g2_n() internal pure returns (G2Point memory n) {
        n.x[0] = uint256(11559732032986387107991004021392285783925812861821192530917403151452391805634);
        n.x[1] = uint256(10857046999023057135944570762232829481370756359578518086990519993285655852781);
        n.y[0] = uint256(17805874995975841540914202342111839520379459829704422454583296818431106115052);
        n.y[1] = uint256(13392588948715843804641432497768002650278120570034223513918757245338268106653);
    }

    function get_target_circuit_g2_s() internal pure returns (G2Point memory s) {
        s.x[0] = uint256(7337269220088280927620402068691938429748050337547090773197167033919349445188);
        s.x[1] = uint256(3770121637545959242509070664098694248699786701464310021860735530167404521320);
        s.y[0] = uint256(10343964991691947571037409447120789505361606418249328495172646462999191672139);
        s.y[1] = uint256(17317880176565749919367963757539077029030327420388252207598334502905927580360);
    }

    function get_target_circuit_g2_n() internal pure returns (G2Point memory n) {
        n.x[0] = uint256(11559732032986387107991004021392285783925812861821192530917403151452391805634);
        n.x[1] = uint256(10857046999023057135944570762232829481370756359578518086990519993285655852781);
        n.y[0] = uint256(17805874995975841540914202342111839520379459829704422454583296818431106115052);
        n.y[1] = uint256(13392588948715843804641432497768002650278120570034223513918757245338268106653);
    }

    function get_wx_wg(uint256[] calldata proof, uint256[6] memory instances)
        internal
        view
        returns (uint256, uint256, uint256, uint256)
    {
        uint256[84] memory m;
        uint256[144] memory absorbing;
        uint256 t0 = 0;
        uint256 t1 = 0;

        
        (t0, t1) = (ecc_mul(9719973778161966041511214979118941943946926332003921125810789499716997978063, 964309539860523890786826090070933402170192256960208347298920628097213090768, instances[0]));
        (t0, t1) = (ecc_mul_add(19632916772423648530889054499766667071644769572589435718862961513767275056267, 4169743395042154154283124499904118697834323494316174356632975583451392937630, instances[1], t0, t1));
        (t0, t1) = (ecc_mul_add(4220290452833385965825076100056752543266169164351225204937465465284891073624, 10573320384447160144710975004904098272044201870530140213271913860613654277810, instances[2], t0, t1));
        (t0, t1) = (ecc_mul_add(14083359361938466987920825409828820161423773080218242199546425415512985370710, 857342720996908058419906415147144396105896650808193752679329204498713064050, instances[3], t0, t1));
        (t0, t1) = (ecc_mul_add(14201365885536601426125447902475267509461156370438952118097070717734527807436, 20865511621281735801354760571722011336875192949835462481710099715399872480074, instances[4], t0, t1));
        (m[0], m[1]) = (ecc_mul_add(4666634617357853921614684275622218147599040468619998570132340426961209492298, 14662827107256826631993420354246931025940859499910752456424170577348323453319, instances[5], t0, t1));
        update_hash_scalar(17646734000565812547645044327649203178034839679417314780384189023562699603555, absorbing, 0);
        update_hash_point(m[0], m[1], absorbing, 2);
        for (t0 = 0; t0 <= 4; t0++) {
            update_hash_point(proof[0 + t0 * 2], proof[1 + t0 * 2], absorbing, 5 + t0 * 3);
        }
        m[2] = (squeeze_challenge(absorbing, 20));
        for (t0 = 0; t0 <= 13; t0++) {
            update_hash_point(proof[10 + t0 * 2], proof[11 + t0 * 2], absorbing, 1 + t0 * 3);
        }
        m[3] = (squeeze_challenge(absorbing, 43));
        m[4] = (squeeze_challenge(absorbing, 1));
        for (t0 = 0; t0 <= 9; t0++) {
            update_hash_point(proof[38 + t0 * 2], proof[39 + t0 * 2], absorbing, 1 + t0 * 3);
        }
        m[5] = (squeeze_challenge(absorbing, 31));
        for (t0 = 0; t0 <= 3; t0++) {
            update_hash_point(proof[58 + t0 * 2], proof[59 + t0 * 2], absorbing, 1 + t0 * 3);
        }
        m[6] = (squeeze_challenge(absorbing, 13));
        for (t0 = 0; t0 <= 70; t0++) {
            update_hash_scalar(proof[66 + t0 * 1], absorbing, 1 + t0 * 2);
        }
        m[7] = (squeeze_challenge(absorbing, 143));
        for (t0 = 0; t0 <= 3; t0++) {
            update_hash_point(proof[137 + t0 * 2], proof[138 + t0 * 2], absorbing, 1 + t0 * 3);
        }
        m[8] = (squeeze_challenge(absorbing, 13));
        m[9] = (mulmod(m[6], 11211301017135681023579411905410872569206244553457844956874280139879520583390, q_mod));
        m[10] = (mulmod(m[6], 10939663269433627367777756708678102241564365262857670666700619874077960926249, q_mod));
        m[11] = (mulmod(m[6], 8734126352828345679573237859165904705806588461301144420590422589042130041188, q_mod));
        m[12] = (fr_pow(m[6], 4194304));
        m[13] = (addmod(m[12], q_mod - 1, q_mod));
        m[14] = (mulmod(21888237653275510688422624196183639687472264873923820041627027729598873448513, m[13], q_mod));
        t0 = (addmod(m[6], q_mod - 1, q_mod));
        m[14] = (fr_div(m[14], t0));
        m[15] = (mulmod(12919475148704033459056799975164749366765443418491560826543287262494049147445, m[13], q_mod));
        t0 = (addmod(m[6], q_mod - 8734126352828345679573237859165904705806588461301144420590422589042130041188, q_mod));
        m[15] = (fr_div(m[15], t0));
        m[16] = (mulmod(2475562068482919789434538161456555368473369493180072113639899532770322825977, m[13], q_mod));
        t0 = (addmod(m[6], q_mod - 2785514556381676080176937710880804108647911392478702105860685610379369825016, q_mod));
        m[16] = (fr_div(m[16], t0));
        m[17] = (mulmod(9952375098572582562392692839581731570430874250722926349774599560449354965478, m[13], q_mod));
        t0 = (addmod(m[6], q_mod - 21710372849001950800533397158415938114909991150039389063546734567764856596059, q_mod));
        m[17] = (fr_div(m[17], t0));
        m[18] = (mulmod(20459617746544248062014976317203465365908990827508925305769002868034509119086, m[13], q_mod));
        t0 = (addmod(m[6], q_mod - 15402826414547299628414612080036060696555554914079673875872749760617770134879, q_mod));
        m[18] = (fr_div(m[18], t0));
        m[19] = (mulmod(496209762031177553439375370250532367801224970379575774747024844773905018536, m[13], q_mod));
        t0 = (addmod(m[6], q_mod - 11016257578652593686382655500910603527869149377564754001549454008164059876499, q_mod));
        m[19] = (fr_div(m[19], t0));
        m[20] = (mulmod(20023042075029862075635603136649050502962424708267292886390647475108663608857, m[13], q_mod));
        t0 = (addmod(m[6], q_mod - 10939663269433627367777756708678102241564365262857670666700619874077960926249, q_mod));
        m[20] = (fr_div(m[20], t0));
        t0 = (addmod(m[15], m[16], q_mod));
        t0 = (addmod(t0, m[17], q_mod));
        t0 = (addmod(t0, m[18], q_mod));
        m[15] = (addmod(t0, m[19], q_mod));
        t0 = (fr_mul_add(proof[74], proof[72], proof[73]));
        t0 = (fr_mul_add(proof[75], proof[67], t0));
        t0 = (fr_mul_add(proof[76], proof[68], t0));
        t0 = (fr_mul_add(proof[77], proof[69], t0));
        t0 = (fr_mul_add(proof[78], proof[70], t0));
        m[16] = (fr_mul_add(proof[79], proof[71], t0));
        t0 = (mulmod(proof[67], proof[68], q_mod));
        m[16] = (fr_mul_add(proof[80], t0, m[16]));
        t0 = (mulmod(proof[69], proof[70], q_mod));
        m[16] = (fr_mul_add(proof[81], t0, m[16]));
        t0 = (addmod(1, q_mod - proof[97], q_mod));
        m[17] = (mulmod(m[14], t0, q_mod));
        t0 = (mulmod(proof[100], proof[100], q_mod));
        t0 = (addmod(t0, q_mod - proof[100], q_mod));
        m[18] = (mulmod(m[20], t0, q_mod));
        t0 = (addmod(proof[100], q_mod - proof[99], q_mod));
        m[19] = (mulmod(t0, m[14], q_mod));
        m[21] = (mulmod(m[3], m[6], q_mod));
        t0 = (addmod(m[20], m[15], q_mod));
        m[15] = (addmod(1, q_mod - t0, q_mod));
        m[22] = (addmod(proof[67], m[4], q_mod));
        t0 = (fr_mul_add(proof[91], m[3], m[22]));
        m[23] = (mulmod(t0, proof[98], q_mod));
        t0 = (addmod(m[22], m[21], q_mod));
        m[22] = (mulmod(t0, proof[97], q_mod));
        m[24] = (mulmod(4131629893567559867359510883348571134090853742863529169391034518566172092834, m[21], q_mod));
        m[25] = (addmod(proof[68], m[4], q_mod));
        t0 = (fr_mul_add(proof[92], m[3], m[25]));
        m[23] = (mulmod(t0, m[23], q_mod));
        t0 = (addmod(m[25], m[24], q_mod));
        m[22] = (mulmod(t0, m[22], q_mod));
        m[24] = (mulmod(4131629893567559867359510883348571134090853742863529169391034518566172092834, m[24], q_mod));
        m[25] = (addmod(proof[69], m[4], q_mod));
        t0 = (fr_mul_add(proof[93], m[3], m[25]));
        m[23] = (mulmod(t0, m[23], q_mod));
        t0 = (addmod(m[25], m[24], q_mod));
        m[22] = (mulmod(t0, m[22], q_mod));
        m[24] = (mulmod(4131629893567559867359510883348571134090853742863529169391034518566172092834, m[24], q_mod));
        t0 = (addmod(m[23], q_mod - m[22], q_mod));
        m[22] = (mulmod(t0, m[15], q_mod));
        m[21] = (mulmod(m[21], 11166246659983828508719468090013646171463329086121580628794302409516816350802, q_mod));
        m[23] = (addmod(proof[70], m[4], q_mod));
        t0 = (fr_mul_add(proof[94], m[3], m[23]));
        m[24] = (mulmod(t0, proof[101], q_mod));
        t0 = (addmod(m[23], m[21], q_mod));
        m[23] = (mulmod(t0, proof[100], q_mod));
        m[21] = (mulmod(4131629893567559867359510883348571134090853742863529169391034518566172092834, m[21], q_mod));
        m[25] = (addmod(proof[71], m[4], q_mod));
        t0 = (fr_mul_add(proof[95], m[3], m[25]));
        m[24] = (mulmod(t0, m[24], q_mod));
        t0 = (addmod(m[25], m[21], q_mod));
        m[23] = (mulmod(t0, m[23], q_mod));
        m[21] = (mulmod(4131629893567559867359510883348571134090853742863529169391034518566172092834, m[21], q_mod));
        m[25] = (addmod(proof[66], m[4], q_mod));
        t0 = (fr_mul_add(proof[96], m[3], m[25]));
        m[24] = (mulmod(t0, m[24], q_mod));
        t0 = (addmod(m[25], m[21], q_mod));
        m[23] = (mulmod(t0, m[23], q_mod));
        m[21] = (mulmod(4131629893567559867359510883348571134090853742863529169391034518566172092834, m[21], q_mod));
        t0 = (addmod(m[24], q_mod - m[23], q_mod));
        m[21] = (mulmod(t0, m[15], q_mod));
        t0 = (addmod(proof[104], m[3], q_mod));
        m[23] = (mulmod(proof[103], t0, q_mod));
        t0 = (addmod(proof[106], m[4], q_mod));
        m[23] = (mulmod(m[23], t0, q_mod));
        m[24] = (mulmod(proof[67], proof[82], q_mod));
        m[2] = (mulmod(0, m[2], q_mod));
        m[24] = (addmod(m[2], m[24], q_mod));
        m[25] = (addmod(m[2], proof[83], q_mod));
        m[26] = (addmod(proof[104], q_mod - proof[106], q_mod));
        t0 = (addmod(1, q_mod - proof[102], q_mod));
        m[27] = (mulmod(m[14], t0, q_mod));
        t0 = (mulmod(proof[102], proof[102], q_mod));
        t0 = (addmod(t0, q_mod - proof[102], q_mod));
        m[28] = (mulmod(m[20], t0, q_mod));
        t0 = (addmod(m[24], m[3], q_mod));
        m[24] = (mulmod(proof[102], t0, q_mod));
        m[25] = (addmod(m[25], m[4], q_mod));
        t0 = (mulmod(m[24], m[25], q_mod));
        t0 = (addmod(m[23], q_mod - t0, q_mod));
        m[23] = (mulmod(t0, m[15], q_mod));
        m[24] = (mulmod(m[14], m[26], q_mod));
        t0 = (addmod(proof[104], q_mod - proof[105], q_mod));
        t0 = (mulmod(m[26], t0, q_mod));
        m[26] = (mulmod(t0, m[15], q_mod));
        t0 = (addmod(proof[109], m[3], q_mod));
        m[29] = (mulmod(proof[108], t0, q_mod));
        t0 = (addmod(proof[111], m[4], q_mod));
        m[29] = (mulmod(m[29], t0, q_mod));
        m[30] = (fr_mul_add(proof[82], proof[68], m[2]));
        m[31] = (addmod(proof[109], q_mod - proof[111], q_mod));
        t0 = (addmod(1, q_mod - proof[107], q_mod));
        m[32] = (mulmod(m[14], t0, q_mod));
        t0 = (mulmod(proof[107], proof[107], q_mod));
        t0 = (addmod(t0, q_mod - proof[107], q_mod));
        m[33] = (mulmod(m[20], t0, q_mod));
        t0 = (addmod(m[30], m[3], q_mod));
        t0 = (mulmod(proof[107], t0, q_mod));
        t0 = (mulmod(t0, m[25], q_mod));
        t0 = (addmod(m[29], q_mod - t0, q_mod));
        m[29] = (mulmod(t0, m[15], q_mod));
        m[30] = (mulmod(m[14], m[31], q_mod));
        t0 = (addmod(proof[109], q_mod - proof[110], q_mod));
        t0 = (mulmod(m[31], t0, q_mod));
        m[31] = (mulmod(t0, m[15], q_mod));
        t0 = (addmod(proof[114], m[3], q_mod));
        m[34] = (mulmod(proof[113], t0, q_mod));
        t0 = (addmod(proof[116], m[4], q_mod));
        m[34] = (mulmod(m[34], t0, q_mod));
        m[35] = (fr_mul_add(proof[82], proof[69], m[2]));
        m[36] = (addmod(proof[114], q_mod - proof[116], q_mod));
        t0 = (addmod(1, q_mod - proof[112], q_mod));
        m[37] = (mulmod(m[14], t0, q_mod));
        t0 = (mulmod(proof[112], proof[112], q_mod));
        t0 = (addmod(t0, q_mod - proof[112], q_mod));
        m[38] = (mulmod(m[20], t0, q_mod));
        t0 = (addmod(m[35], m[3], q_mod));
        t0 = (mulmod(proof[112], t0, q_mod));
        t0 = (mulmod(t0, m[25], q_mod));
        t0 = (addmod(m[34], q_mod - t0, q_mod));
        m[34] = (mulmod(t0, m[15], q_mod));
        m[35] = (mulmod(m[14], m[36], q_mod));
        t0 = (addmod(proof[114], q_mod - proof[115], q_mod));
        t0 = (mulmod(m[36], t0, q_mod));
        m[36] = (mulmod(t0, m[15], q_mod));
        t0 = (addmod(proof[119], m[3], q_mod));
        m[39] = (mulmod(proof[118], t0, q_mod));
        t0 = (addmod(proof[121], m[4], q_mod));
        m[39] = (mulmod(m[39], t0, q_mod));
        m[40] = (fr_mul_add(proof[82], proof[70], m[2]));
        m[41] = (addmod(proof[119], q_mod - proof[121], q_mod));
        t0 = (addmod(1, q_mod - proof[117], q_mod));
        m[42] = (mulmod(m[14], t0, q_mod));
        t0 = (mulmod(proof[117], proof[117], q_mod));
        t0 = (addmod(t0, q_mod - proof[117], q_mod));
        m[43] = (mulmod(m[20], t0, q_mod));
        t0 = (addmod(m[40], m[3], q_mod));
        t0 = (mulmod(proof[117], t0, q_mod));
        t0 = (mulmod(t0, m[25], q_mod));
        t0 = (addmod(m[39], q_mod - t0, q_mod));
        m[25] = (mulmod(t0, m[15], q_mod));
        m[39] = (mulmod(m[14], m[41], q_mod));
        t0 = (addmod(proof[119], q_mod - proof[120], q_mod));
        t0 = (mulmod(m[41], t0, q_mod));
        m[40] = (mulmod(t0, m[15], q_mod));
        t0 = (addmod(proof[124], m[3], q_mod));
        m[41] = (mulmod(proof[123], t0, q_mod));
        t0 = (addmod(proof[126], m[4], q_mod));
        m[41] = (mulmod(m[41], t0, q_mod));
        m[44] = (fr_mul_add(proof[84], proof[67], m[2]));
        m[45] = (addmod(m[2], proof[85], q_mod));
        m[46] = (addmod(proof[124], q_mod - proof[126], q_mod));
        t0 = (addmod(1, q_mod - proof[122], q_mod));
        m[47] = (mulmod(m[14], t0, q_mod));
        t0 = (mulmod(proof[122], proof[122], q_mod));
        t0 = (addmod(t0, q_mod - proof[122], q_mod));
        m[48] = (mulmod(m[20], t0, q_mod));
        t0 = (addmod(m[44], m[3], q_mod));
        m[44] = (mulmod(proof[122], t0, q_mod));
        t0 = (addmod(m[45], m[4], q_mod));
        t0 = (mulmod(m[44], t0, q_mod));
        t0 = (addmod(m[41], q_mod - t0, q_mod));
        m[41] = (mulmod(t0, m[15], q_mod));
        m[44] = (mulmod(m[14], m[46], q_mod));
        t0 = (addmod(proof[124], q_mod - proof[125], q_mod));
        t0 = (mulmod(m[46], t0, q_mod));
        m[45] = (mulmod(t0, m[15], q_mod));
        t0 = (addmod(proof[129], m[3], q_mod));
        m[46] = (mulmod(proof[128], t0, q_mod));
        t0 = (addmod(proof[131], m[4], q_mod));
        m[46] = (mulmod(m[46], t0, q_mod));
        m[49] = (fr_mul_add(proof[86], proof[67], m[2]));
        m[50] = (addmod(m[2], proof[87], q_mod));
        m[51] = (addmod(proof[129], q_mod - proof[131], q_mod));
        t0 = (addmod(1, q_mod - proof[127], q_mod));
        m[52] = (mulmod(m[14], t0, q_mod));
        t0 = (mulmod(proof[127], proof[127], q_mod));
        t0 = (addmod(t0, q_mod - proof[127], q_mod));
        m[53] = (mulmod(m[20], t0, q_mod));
        t0 = (addmod(m[49], m[3], q_mod));
        m[49] = (mulmod(proof[127], t0, q_mod));
        t0 = (addmod(m[50], m[4], q_mod));
        t0 = (mulmod(m[49], t0, q_mod));
        t0 = (addmod(m[46], q_mod - t0, q_mod));
        m[46] = (mulmod(t0, m[15], q_mod));
        m[49] = (mulmod(m[14], m[51], q_mod));
        t0 = (addmod(proof[129], q_mod - proof[130], q_mod));
        t0 = (mulmod(m[51], t0, q_mod));
        m[50] = (mulmod(t0, m[15], q_mod));
        t0 = (addmod(proof[134], m[3], q_mod));
        m[51] = (mulmod(proof[133], t0, q_mod));
        t0 = (addmod(proof[136], m[4], q_mod));
        m[51] = (mulmod(m[51], t0, q_mod));
        m[54] = (fr_mul_add(proof[88], proof[67], m[2]));
        m[2] = (addmod(m[2], proof[89], q_mod));
        m[55] = (addmod(proof[134], q_mod - proof[136], q_mod));
        t0 = (addmod(1, q_mod - proof[132], q_mod));
        m[56] = (mulmod(m[14], t0, q_mod));
        t0 = (mulmod(proof[132], proof[132], q_mod));
        t0 = (addmod(t0, q_mod - proof[132], q_mod));
        m[20] = (mulmod(m[20], t0, q_mod));
        t0 = (addmod(m[54], m[3], q_mod));
        m[3] = (mulmod(proof[132], t0, q_mod));
        t0 = (addmod(m[2], m[4], q_mod));
        t0 = (mulmod(m[3], t0, q_mod));
        t0 = (addmod(m[51], q_mod - t0, q_mod));
        m[2] = (mulmod(t0, m[15], q_mod));
        m[3] = (mulmod(m[14], m[55], q_mod));
        t0 = (addmod(proof[134], q_mod - proof[135], q_mod));
        t0 = (mulmod(m[55], t0, q_mod));
        m[4] = (mulmod(t0, m[15], q_mod));
        t0 = (fr_mul_add(m[5], 0, m[16]));
        t0 = (fr_mul_add_mt(m, m[5], 24064768791442479290152634096194013545513974547709823832001394403118888981009, t0));
        t0 = (fr_mul_add_mt(m, m[5], 4704208815882882920750, t0));
        m[2] = (fr_div(t0, m[13]));
        m[3] = (mulmod(m[8], m[8], q_mod));
        m[4] = (mulmod(m[3], m[8], q_mod));
        (t0, t1) = (ecc_mul(proof[143], proof[144], m[4]));
        (t0, t1) = (ecc_mul_add_pm(m, proof, 281470825071501, t0, t1));
        (m[14], m[15]) = (ecc_add(t0, t1, proof[137], proof[138]));
        m[5] = (mulmod(m[4], m[11], q_mod));
        m[11] = (mulmod(m[4], m[7], q_mod));
        m[13] = (mulmod(m[11], m[7], q_mod));
        m[16] = (mulmod(m[13], m[7], q_mod));
        m[17] = (mulmod(m[16], m[7], q_mod));
        m[18] = (mulmod(m[17], m[7], q_mod));
        m[19] = (mulmod(m[18], m[7], q_mod));
        t0 = (mulmod(m[19], proof[135], q_mod));
        t0 = (fr_mul_add_pm(m, proof, 79227007564587019091207590530, t0));
        m[20] = (fr_mul_add(proof[105], m[4], t0));
        m[10] = (mulmod(m[3], m[10], q_mod));
        m[20] = (fr_mul_add(proof[99], m[3], m[20]));
        m[9] = (mulmod(m[8], m[9], q_mod));
        m[21] = (mulmod(m[8], m[7], q_mod));
        for (t0 = 0; t0 < 8; t0++) {
            m[22 + t0 * 1] = (mulmod(m[21 + t0 * 1], m[7 + t0 * 0], q_mod));
        }
        t0 = (mulmod(m[29], proof[133], q_mod));
        t0 = (fr_mul_add_pm(m, proof, 1461480058012745347196003969984389955172320353408, t0));
        m[20] = (addmod(m[20], t0, q_mod));
        m[3] = (addmod(m[3], m[21], q_mod));
        m[21] = (mulmod(m[7], m[7], q_mod));
        m[30] = (mulmod(m[21], m[7], q_mod));
        for (t0 = 0; t0 < 50; t0++) {
            m[31 + t0 * 1] = (mulmod(m[30 + t0 * 1], m[7 + t0 * 0], q_mod));
        }
        m[81] = (mulmod(m[80], proof[90], q_mod));
        m[82] = (mulmod(m[79], m[12], q_mod));
        m[83] = (mulmod(m[82], m[12], q_mod));
        m[12] = (mulmod(m[83], m[12], q_mod));
        t0 = (fr_mul_add(m[79], m[2], m[81]));
        t0 = (fr_mul_add_pm(m, proof, 28637501128329066231612878461967933875285131620580756137874852300330784214624, t0));
        t0 = (fr_mul_add_pm(m, proof, 21474593857386732646168474467085622855647258609351047587832868301163767676495, t0));
        t0 = (fr_mul_add_pm(m, proof, 14145600374170319983429588659751245017860232382696106927048396310641433325177, t0));
        t0 = (fr_mul_add_pm(m, proof, 18446470583433829957, t0));
        t0 = (addmod(t0, proof[66], q_mod));
        m[2] = (addmod(m[20], t0, q_mod));
        m[19] = (addmod(m[19], m[54], q_mod));
        m[20] = (addmod(m[29], m[53], q_mod));
        m[18] = (addmod(m[18], m[51], q_mod));
        m[28] = (addmod(m[28], m[50], q_mod));
        m[17] = (addmod(m[17], m[48], q_mod));
        m[27] = (addmod(m[27], m[47], q_mod));
        m[16] = (addmod(m[16], m[45], q_mod));
        m[26] = (addmod(m[26], m[44], q_mod));
        m[13] = (addmod(m[13], m[42], q_mod));
        m[25] = (addmod(m[25], m[41], q_mod));
        m[11] = (addmod(m[11], m[39], q_mod));
        m[24] = (addmod(m[24], m[38], q_mod));
        m[4] = (addmod(m[4], m[36], q_mod));
        m[23] = (addmod(m[23], m[35], q_mod));
        m[22] = (addmod(m[22], m[34], q_mod));
        m[3] = (addmod(m[3], m[33], q_mod));
        m[8] = (addmod(m[8], m[32], q_mod));
        (t0, t1) = (ecc_mul(proof[143], proof[144], m[5]));
        (t0, t1) = (ecc_mul_add_pm(m, proof, 10933423423422768024429730621579321771439401845242250760130969989159573132066, t0, t1));
        (t0, t1) = (ecc_mul_add_pm(m, proof, 1461486238301980199876269201563775120819706402602, t0, t1));
        (t0, t1) = (ecc_mul_add(3906568189245118222085154723247775601841511223438457095207572782994992780043, 3819224242810725756363282531968196581494781879171744784533311152973188401197, m[78], t0, t1));
        (t0, t1) = (ecc_mul_add(9596203497862615834790822209009471133473520637144491394693744066966104104943, 5416354475775464554827771708790975624480423918471775023378771866084067421667, m[77], t0, t1));
        (t0, t1) = (ecc_mul_add(387808454611658811110267919969206986445748013921909436559796997539484991850, 5676087424621940389398269326984649955190820150505105394190441118352336353583, m[76], t0, t1));
        (t0, t1) = (ecc_mul_add(2235424148890903031270970633506685307746515863576804399392784742315034461636, 11026005882559078448875759200247457774938304748981730707714303134693091571819, m[75], t0, t1));
        (t0, t1) = (ecc_mul_add(16845700762804892391321441815667405013405024624667756618028108995224579946812, 5965294324407971836520902415764608906416433305769557525003620429530800639863, m[74], t0, t1));
        (t0, t1) = (ecc_mul_add(6359131555879868951900524683872500817807704303725367738788220884913005271878, 1559740560803575057608472438734556959279581767886644863946953287649507704207, m[73], t0, t1));
        (t0, t1) = (ecc_mul_add(4531515010330539686848655321311504807821080078116243914583623167066807540624, 9402610136108392378148761190860723559111911392428988924211780796791879639585, m[72], t0, t1));
        (t0, t1) = (ecc_mul_add(11053928432352483233055992698802253083953495961364232193064009014033283507751, 466709553843166819269114145283374844833192581124353385788893986763966941283, m[71], t0, t1));
        (t0, t1) = (ecc_mul_add(7339784453325921357094554910468052224411072162496074677656430991883189615949, 8610569312855334384581033013281681643730465376355947016423249251095115943514, m[70], t0, t1));
        (t0, t1) = (ecc_mul_add(11382321911693927171068000887748429690092801007297392303148653405231668766577, 14317063454679043685489847725731076636467672766037281677982873245311137711052, m[69], t0, t1));
        (t0, t1) = (ecc_mul_add(4531515010330539686848655321311504807821080078116243914583623167066807540624, 9402610136108392378148761190860723559111911392428988924211780796791879639585, m[68], t0, t1));
        (t0, t1) = (ecc_mul_add(7398839374304247105968274715301516100083997737350105971903995300804136130384, 16295586857254494259783419243316209049269450443591667779161249545750884992576, m[67], t0, t1));
        (t0, t1) = (ecc_mul_add(2916923238921978135902227042935900128671946543388679763029616281420360164244, 15979789148416068238273329952723506430043291744555067740015677856196240594760, m[66], t0, t1));
        (t0, t1) = (ecc_mul_add(17561725035442510250960446575224794082248933379400761155443996123908958092305, 13320826428444446202981602319793462405280693341323790387955739250846092794714, m[65], t0, t1));
        (t0, t1) = (ecc_mul_add(1458548178907670028441906219603047451171797963361087441644459092869334185324, 1399899293121253164817533725035944297917880081481003695559586083539056458000, m[64], t0, t1));
        (t0, t1) = (ecc_mul_add(9363964946497449929205879942852053319926640008403538781723633696578177457007, 12381261474219417913460674828279638958637116519464111171471173356163958338248, m[63], t0, t1));
        (t0, t1) = (ecc_mul_add(3893837508052669112117930923641152399711074585014458265880025382355442375832, 20240084873931210323705772091612683244326858522436080123331551354785527609281, m[62], t0, t1));
        (t0, t1) = (ecc_mul_add(16238678022843899968779297737894758982610890490076380091004940429180123490404, 21143739295942301792883362130356983453339170986351388878413259501010054968969, m[61], t0, t1));
        (t0, t1) = (ecc_mul_add(21281809813969075750844835050637790455777084590165733752727918105436988201815, 11455579600620697654575040809664201484793202168367794384978938942576191476380, m[60], t0, t1));
        (t0, t1) = (ecc_mul_add(17163656770698762513242784942408260686753033065598307122468493920591796445657, 2083019109157958828615217040746737620346487402055012641521068376465140624235, m[59], t0, t1));
        (t0, t1) = (ecc_mul_add(6330937473919448973388460860768098920987782521135251373191777115109561102269, 8224395417346834173185846737467979735215749456848890699737569443030892044554, m[58], t0, t1));
        (t0, t1) = (ecc_mul_add(17922970557930911466193516794228165600328694433834552639801126880573179738701, 16412189643470890217551013743560072608534963476619083532976768968091617898805, m[57], t0, t1));
        (t0, t1) = (ecc_mul_add(6272666014146809016234723113576653804162884871807644945918489392263815035516, 5430828026291186977317491725455302155581981298640808102119856844897502521195, m[56], t0, t1));
        (t0, t1) = (ecc_mul_add_pm(m, proof, 6277008573546246765208814532330797927747086570010716419876, t0, t1));
        (m[0], m[1]) = (ecc_add(t0, t1, m[0], m[1]));
        (t0, t1) = (ecc_mul(1, 2, m[2]));
        (m[0], m[1]) = (ecc_sub(m[0], m[1], t0, t1));
        return (m[14], m[15], m[0], m[1]);
    }

    function verify(
        uint256[] calldata proof,
        uint256[] calldata target_circuit_final_pair
    ) external {
        uint256[6] memory instances;
        instances[0] = target_circuit_final_pair[0] & ((1 << 136) - 1);
        instances[1] = (target_circuit_final_pair[0] >> 136) + ((target_circuit_final_pair[1] & 1) << 136);
        instances[2] = target_circuit_final_pair[2] & ((1 << 136) - 1);
        instances[3] = (target_circuit_final_pair[2] >> 136) + ((target_circuit_final_pair[3] & 1) << 136);
        
        instances[4] = target_circuit_final_pair[4];
        instances[5] = target_circuit_final_pair[5];

        uint256 x0 = 0;
        uint256 x1 = 0;
        uint256 y0 = 0;
        uint256 y1 = 0;

        G1Point[] memory g1_points = new G1Point[](2);
        G2Point[] memory g2_points = new G2Point[](2);
        bool checked = false;

        (x0, y0, x1, y1) = get_wx_wg(proof, instances);
        g1_points[0].x = x0;
        g1_points[0].y = y0;
        g1_points[1].x = x1;
        g1_points[1].y = y1;
        g2_points[0] = get_verify_circuit_g2_s();
        g2_points[1] = get_verify_circuit_g2_n();

        checked = pairing(g1_points, g2_points);
        require(checked);

        g1_points[0].x = target_circuit_final_pair[0];
        g1_points[0].y = target_circuit_final_pair[1];
        g1_points[1].x = target_circuit_final_pair[2];
        g1_points[1].y = target_circuit_final_pair[3];
        g2_points[0] = get_target_circuit_g2_s();
        g2_points[1] = get_target_circuit_g2_n();

        checked = pairing(g1_points, g2_points);
        // require(checked);
    }
}
