rule AsyncRAT_Own_Client_Strings
{
    meta:
        author = "AsyncParser"
        description = "Independent AsyncRAT client strings; source-derived, no overlap with rat-king-parser or Elastic Windows_Trojan_Asyncrat_11a11ba1"
        source_repo = "https://github.com/NYAN-x-CAT/AsyncRAT-C-Sharp"
        source_commit = "0f0cba4ec3985c38082c6abb3e1e01895120ffb6"
        date = "2026-11-27"
        license = "Own rule, source strings only"

    strings:
        // source: AsyncRAT-C#/Client/Algorithm/Aes256.cs:113
        $mac_error = "Invalid message authentication code (MAC)." wide ascii
        // source: AsyncRAT-C#/Client/Algorithm/Aes256.cs:52 (nameof(input) compiles to this literal)
        $input_null = "input can not be null." wide ascii
        // source: AsyncRAT-C#/Client/Helper/Anti_Analysis.cs:57
        $wmi_computer = "Select * from Win32_ComputerSystem" wide ascii
        // source: AsyncRAT-C#/Client/Helper/Anti_Analysis.cs:96
        $sbie_dll = "SbieDll.dll" wide ascii
        // source: AsyncRAT-C#/Client/Helper/CheckMiner.cs:15
        $miner_flag = "--donate-level=" wide ascii
        // source: AsyncRAT-C#/Client/Helper/CheckMiner.cs:31
        $wmi_process = "SELECT CommandLine FROM Win32_Process WHERE ProcessId = " wide ascii
        // source: AsyncRAT-C#/Client/Helper/Methods.cs:39
        $security_center = "\\root\\SecurityCenter2" wide ascii
        // source: AsyncRAT-C#/Client/Helper/Methods.cs:39
        $av_product = "Select * from AntivirusProduct" wide ascii
        // source: AsyncRAT-C#/Client/Helper/HwidGen.cs:22
        $hwid_error = "Err HWID" wide ascii
        // source: AsyncRAT-C#/Client/Handle Packet/Packet.cs:44
        $send_plugin = "sendPlugin" wide ascii
        // source: AsyncRAT-C#/Client/Handle Packet/Packet.cs:58
        $save_plugin = "savePlugin" wide ascii
        // source: AsyncRAT-C#/Client/Handle Packet/Packet.cs:61
        $plugin_saved = "plugin saved" wide ascii
        // source: AsyncRAT-C#/Client/Helper/IdSender.cs:14
        $client_info = "ClientInfo" wide ascii

    condition:
        uint16(0) == 0x5A4D and 4 of them
}
