# OPC UA Traffic Analyser: uanalyser

## Information

Below are the guide tables with essential information about the test files used in the development of this tool

<!--<style type="text/css">
.tg  {border-collapse:collapse;border-color:#ccc;border-spacing:0;border:1px solid #ddd;}
.tg td{background-color:#fff;border-bottom-width:1px;border-color:#ccc;border-style:solid;border-top-width:1px; border-width:0px;color:#333;font-family:Arial, sans-serif;font-size:14px;overflow:hidden;padding:10px 5px; word-break:normal;}
.tg th{background-color:#f0f0f0;border-bottom-width:1px;border-color:#ccc;border-style:solid;border-top-width:1px; border-width:0px;color:#333;font-family:Arial, sans-serif;font-size:14px;font-weight:normal;overflow:hidden; padding:10px 5px;word-break:normal;}
.tg .header{border-color:inherit;font-weight:bold;text-align:center;vertical-align:center}
.tg .hd-name, .tg .name{width: 200px; word-wrap: break-word;}
.tg tbody tr:nth-child(even) {background-color: #f2f2f2;}
</style>-->
<table class="tg">
<thead>
  <tr>
    <th class="hd hd-type">Type</th>
    <th class="hd hd-name">File Name</th>
    <th class="hd hd-size">Size</th>
    <th class="hd hd-server">Server</th>
    <th class="hd hd-client">Client</th>
    <th class="hd hd-attacker">Attacker</th>
    <th class="hd hd-sniffer">Sniffer</th>
    <th class="hd hd-attacker">Attack</th>
  </tr>
</thead>
<tbody>
    <tr>
    <td rowspan="8" class="type">0</td>
    <td class="name">dos_certificate_inf_chain_loop</td>
    <td class="size">7997</td>
    <td class="server">192.168.164.101<br>e4:5f:01:2e:1a:b6</td>
    <td class="client">192.168.164.102<br>e4:5f:01:2e:1b:c1</td>
    <td class="attacker">192.168.164.103<br>00:09:5b:bd:64:06</td>
    <td class="sniffer">192.168.164.115<br>ac:1a:3d:a8:67:cd</td>
    <td class="attack">Nº: 1967<br>Time: 32.3419</td>
  </tr>
  <tr>
    <td class="name">dos_function_call_null_deref</td>
    <td class="size">8805</td>
    <td class="server">192.168.164.101<br>e4:5f:01:2e:1a:b6</td>
    <td class="client">192.168.164.102<br>e4:5f:01:2e:1b:c1</td>
    <td class="attacker">192.168.164.103<br>00:09:5b:bd:64:06</td>
    <td class="sniffer">192.168.164.115<br>ac:1a:3d:a8:67:cd</td>
    <td class="attack">Nº: 2275<br>Time: 31.7939</td>
  </tr>
  <tr>
    <td class="name">dos_hping3</td>
    <td class="size">3521545</td>
    <td class="server">192.168.164.101<br>e4:5f:01:2e:1a:b6</td>
    <td class="client">192.168.164.102<br>e4:5f:01:2e:1b:c1</td>
    <td class="attacker">192.168.164.201<br>00:09:5b:bd:64:06</td>
    <td class="sniffer">192.168.164.115<br>ac:1a:3d:a8:67:cd</td>
    <td class="attack">Nº: 4294<br>Time: 41.1575</td>
  </tr>
  <tr>
    <td class="name">dos_open_multiple_secure_channels</td>
    <td class="size">21200</td>
    <td class="server">192.168.164.101<br>e4:5f:01:2e:1a:b6</td>
    <td class="client">192.168.164.102<br>e4:5f:01:2e:1b:c1</td>
    <td class="attacker">192.168.164.103<br>00:09:5b:bd:64:06</td>
    <td class="sniffer">192.168.164.115<br>ac:1a:3d:a8:67:cd</td>
    <td class="attack">Nº: 2224<br>Time: 32.9595</td>
  </tr>
  <tr>
    <td class="name">dos_translate_browse_path_call_stack_overflow</td>
    <td class="size">8759</td>
    <td class="server">192.168.164.101<br>e4:5f:01:2e:1a:b6</td>
    <td class="client">192.168.164.102<br>e4:5f:01:2e:1b:c1</td>
    <td class="attacker">192.168.164.103<br>00:09:5b:bd:64:06</td>
    <td class="sniffer">192.168.164.115<br>ac:1a:3d:a8:67:cd</td>
    <td class="attack">Nº: 2366<br>Time: 31.7897</td>
  </tr>
  <tr>
    <td class="name">mitm_arp</td>
    <td class="size">6059</td>
    <td class="server">192.168.164.101<br>e4:5f:01:2e:1a:b6</td>
    <td class="client">192.168.164.102<br>e4:5f:01:2e:1b:c1</td>
    <td class="attacker">-<br>00:09:5b:bd:64:06</td>
    <td class="sniffer">192.168.164.110<br>00:be:43:34:b8:54</td>
    <td class="attack">-</td>
  </tr>
  <tr>
    <td class="name">mitm_port</td>
    <td class="size">619200</td>
    <td class="server">192.168.164.101<br>e4:5f:01:2e:1a:b6</td>
    <td class="client">192.168.164.102<br>e4:5f:01:2e:1b:c1</td>
    <td class="attacker">-<br>00:09:5b:bd:64:06</td>
    <td class="sniffer">192.168.164.110<br>00:be:43:34:b8:54</td>
    <td class="attack">-</td>
  </tr>
  <tr>
    <td class="name">normal_local_server</td>
    <td class="size">6129</td>
    <td class="server">192.168.164.101<br>e4:5f:01:2e:1a:b6</td>
    <td class="client">192.168.164.102<br>e4:5f:01:2e:1b:c1</td>
    <td class="attacker">-</td>
    <td class="sniffer">192.168.164.110<br>00:be:43:34:b8:54</td>
    <td class="attack">-</td>
  </tr>
  <tr>
    <td rowspan="8" class="type">1</td>
    <td class="name">dos_certificate_inf_chain_loop</td>
    <td class="size">8811</td>
    <td class="server">192.168.164.101<br>e4:5f:01:2e:1a:b6</td>
    <td class="client">192.168.164.102<br>e4:5f:01:2e:1b:c1</td>
    <td class="attacker">192.168.164.103<br>00:09:5b:bd:64:06</td>
    <td class="sniffer">192.168.164.115<br>ac:1a:3d:a8:67:cd</td>
    <td class="attack">Nº: 3470<br>Time: 32.2758</td>
  </tr>
  <tr>
    <td class="name">dos_function_call_null_deref</td>
    <td class="size">52709</td>
    <td class="server">192.168.164.101<br>e4:5f:01:2e:1a:b6</td>
    <td class="client">192.168.164.102<br>e4:5f:01:2e:1b:c1</td>
    <td class="attacker">192.168.164.103<br>00:09:5b:bd:64:06</td>
    <td class="sniffer">192.168.164.115<br>ac:1a:3d:a8:67:cd</td>
    <td class="attack">Nº: 2814<br>Time: 30.9477</td>
  </tr>
  <tr>
    <td class="name">dos_hping3</td>
    <td class="size">2065664</td>
    <td class="server">192.168.164.101<br>e4:5f:01:2e:1a:b6</td>
    <td class="client">192.168.164.102<br>e4:5f:01:2e:1b:c1</td>
    <td class="attacker">192.168.164.201<br>00:09:5b:bd:64:06</td>
    <td class="sniffer">192.168.164.115<br>ac:1a:3d:a8:67:cd</td>
    <td class="attack">Nº: 4275<br>Time: 45.8889</td>
  </tr>
  <tr>
    <td class="name">dos_open_multiple_secure_channels</td>
    <td class="size">22739</td>
    <td class="server">192.168.164.101<br>e4:5f:01:2e:1a:b6</td>
    <td class="client">192.168.164.102<br>e4:5f:01:2e:1b:c1</td>
    <td class="attacker">192.168.164.103<br>00:09:5b:bd:64:06</td>
    <td class="sniffer">192.168.164.115<br>ac:1a:3d:a8:67:cd</td>
    <td class="attack">Nº: 3540<br>Time: 31.8013 </td>
  </tr>
  <tr>
    <td class="name">dos_translate_browse_path_call_stack_overflow</td>
    <td class="size">9362</td>
    <td class="server">192.168.164.101<br>e4:5f:01:2e:1a:b6</td>
    <td class="client">192.168.164.102<br>e4:5f:01:2e:1b:c1</td>
    <td class="attacker">192.168.164.103<br>00:09:5b:bd:64:06</td>
    <td class="sniffer">192.168.164.115<br>ac:1a:3d:a8:67:cd</td>
    <td class="attack">Nº: 3397<br>Time: 31.7899</td>
  </tr>
  <tr>
    <td class="name">mitm_arp</td>
    <td class="size">7650</td>
    <td class="server">192.168.164.101<br>e4:5f:01:2e:1a:b6</td>
    <td class="client">192.168.164.102<br>e4:5f:01:2e:1b:c1</td>
    <td class="attacker">-<br>00:09:5b:bd:64:06</td>
    <td class="sniffer">192.168.164.110<br>00:be:43:34:b8:54</td>
    <td class="attack">-</td>
  </tr>
  <tr>
    <td class="name">mitm_port</td>
    <td class="size">601152</td>
    <td class="server">192.168.164.101<br>e4:5f:01:2e:1a:b6</td>
    <td class="client">192.168.164.102<br>e4:5f:01:2e:1b:c1</td>
    <td class="attacker"><br>00:09:5b:bd:64:06</td>
    <td class="sniffer">192.168.164.110<br>00:be:43:34:b8:54</td>
    <td class="attack">-</td>
  </tr>
  <tr>
    <td class="name">normal_local_server</td>
    <td class="size">13861</td>
    <td class="server">192.168.164.101<br>e4:5f:01:2e:1a:b6</td>
    <td class="client">192.168.164.102<br>e4:5f:01:2e:1b:c1</td>
    <td class="attacker">-</td>
    <td class="sniffer">192.168.164.110<br>00:be:43:34:b8:54</td>
    <td class="attack">-</td>
  </tr>
  <tr>
    <td rowspan="8" class="type">2</td>
    <td class="name">dos_certificate_inf_chain_loop</td>
    <td class="size">8686</td>
    <td class="server">192.168.164.101<br>e4:5f:01:2e:1a:b6</td>
    <td class="client">192.168.164.102<br>e4:5f:01:2e:1b:c1</td>
    <td class="attacker">192.168.164.103<br>00:09:5b:bd:64:06</td>
    <td class="sniffer">192.168.164.115<br>ac:1a:3d:a8:67:cd</td>
    <td class="attack">Nº: 3225<br>Time: 32.3843</td>
  </tr>
  <tr>
    <td class="name">dos_function_call_null_deref</td>
    <td class="size">53351</td>
    <td class="server">192.168.164.101<br>e4:5f:01:2e:1a:b6</td>
    <td class="client">192.168.164.102<br>e4:5f:01:2e:1b:c1</td>
    <td class="attacker">192.168.164.103<br>00:09:5b:bd:64:06</td>
    <td class="sniffer">192.168.164.115<br>ac:1a:3d:a8:67:cd</td>
    <td class="attack">Nº: 3338<br>Time: 31.6231</td>
  </tr>
  <tr>
    <td class="name">dos_hping3</td>
    <td class="size">2203825</td>
    <td class="server">192.168.164.101<br>e4:5f:01:2e:1a:b6</td>
    <td class="client">192.168.164.102<br>e4:5f:01:2e:1b:c1</td>
    <td class="attacker">192.168.164.201<br>00:09:5b:bd:64:06</td>
    <td class="sniffer">192.168.164.115<br>ac:1a:3d:a8:67:cd</td>
    <td class="attack">Nº: 5566<br>Time: 44.9302</td>
  </tr>
  <tr>
    <td class="name">dos_open_multiple_secure_channels</td>
    <td class="size">21213</td>
    <td class="server">192.168.164.101<br>e4:5f:01:2e:1a:b6</td>
    <td class="client">192.168.164.102<br>e4:5f:01:2e:1b:c1</td>
    <td class="attacker">192.168.164.103<br>00:09:5b:bd:64:06</td>
    <td class="sniffer">192.168.164.115<br>ac:1a:3d:a8:67:cd</td>
    <td class="attack">Nº: 3292<br>Time: 31.7924</td>
  </tr>
  <tr>
    <td class="name">dos_translate_browse_path_call_stack_overflow</td>
    <td class="size">9437</td>
    <td class="server">192.168.164.101<br>e4:5f:01:2e:1a:b6</td>
    <td class="client">192.168.164.102<br>e4:5f:01:2e:1b:c1</td>
    <td class="attacker">192.168.164.103<br>00:09:5b:bd:64:06</td>
    <td class="sniffer">192.168.164.115<br>ac:1a:3d:a8:67:cd</td>
    <td class="attack">Nº: 3464<br>Time: 31.1787</td>
  </tr>
  <tr>
    <td class="name">mitm_arp</td>
    <td class="size">6407</td>
    <td class="server">192.168.164.101<br>e4:5f:01:2e:1a:b6</td>
    <td class="client">192.168.164.102<br>e4:5f:01:2e:1b:c1</td>
    <td class="attacker">-<br>00:09:5b:bd:64:06</td>
    <td class="sniffer">192.168.164.110<br>00:be:43:34:b8:54</td>
    <td class="attack">-</td>
  </tr>
  <tr>
    <td class="name">mitm_port</td>
    <td class="size">600451</td>
    <td class="server">192.168.164.101<br>e4:5f:01:2e:1a:b6</td>
    <td class="client">192.168.164.102<br>e4:5f:01:2e:1b:c1</td>
    <td class="attacker">-<br>00:09:5b:bd:64:06</td>
    <td class="sniffer">192.168.164.110<br>00:be:43:34:b8:54</td>
    <td class="attack">-</td>
  </tr>
  <tr>
    <td class="name">normal_local_server</td>
    <td class="size">33034</td>
    <td class="server">192.168.164.101<br>e4:5f:01:2e:1a:b6</td>
    <td class="client">192.168.164.102<br>e4:5f:01:2e:1b:c1</td>
    <td class="attacker">-</td>
    <td class="sniffer">192.168.164.110<br>00:be:43:34:b8:54</td>
    <td class="attack">-</td>
  </tr>
</tbody>
</table>
