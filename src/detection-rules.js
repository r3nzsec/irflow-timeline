// Process tree chain-based detection rules — 342 rules from irflow-detection-rules.sql
// Format: [parent, child, severity(0-3), description with MITRE ATT&CK technique]
const CHAIN_RULES = [
// Execution
["winword.exe","cmd.exe",3,"Word \u2192 cmd \u2014 macro execution [T1204.002]"],
["winword.exe","powershell.exe",3,"Word \u2192 PS \u2014 macro execution [T1059.001]"],
["winword.exe","wscript.exe",3,"Word \u2192 WScript \u2014 VBS macro dropper [T1059.005]"],
["winword.exe","cscript.exe",3,"Word \u2192 CScript \u2014 VBS macro dropper [T1059.005]"],
["winword.exe","msdt.exe",3,"Word \u2192 msdt \u2014 Follina (CVE-2022-30190) [T1203]"],
["winword.exe","bash.exe",3,"Word \u2192 bash \u2014 unusual execution chain [T1059.004]"],
["excel.exe","cmd.exe",3,"Excel \u2192 cmd \u2014 macro/DDE execution [T1204.002]"],
["excel.exe","powershell.exe",3,"Excel \u2192 PS \u2014 macro execution [T1059.001]"],
["excel.exe","wscript.exe",3,"Excel \u2192 WScript \u2014 VBS dropper [T1059.005]"],
["excel.exe","cscript.exe",3,"Excel \u2192 CScript \u2014 VBS dropper [T1059.005]"],
["powerpnt.exe","cmd.exe",3,"PPT \u2192 cmd \u2014 action/macro [T1204.002]"],
["powerpnt.exe","powershell.exe",3,"PPT \u2192 PS \u2014 action/macro [T1059.001]"],
["powerpnt.exe","wscript.exe",3,"PPT \u2192 WScript \u2014 PPT spawning WScript [T1059.005]"],
["outlook.exe","cmd.exe",2,"Outlook \u2192 cmd \u2014 embedded object or preview [T1566.001]"],
["outlook.exe","powershell.exe",3,"Outlook \u2192 PS \u2014 phishing execution [T1566.001]"],
["outlook.exe","wscript.exe",2,"Outlook \u2192 WScript \u2014 script attachment [T1566.001]"],
["outlook.exe","cscript.exe",2,"Outlook \u2192 CScript \u2014 script attachment [T1566.001]"],
["outlook.exe","msdt.exe",3,"Outlook \u2192 msdt \u2014 Follina variant [T1203]"],
["onenote.exe","cmd.exe",3,"OneNote \u2192 cmd \u2014 embedded script/HTA [T1204.002]"],
["onenote.exe","powershell.exe",3,"OneNote \u2192 PS \u2014 embedded payload [T1059.001]"],
["onenote.exe","wscript.exe",3,"OneNote \u2192 WScript \u2014 embedded VBS [T1059.005]"],
["onenote.exe","cscript.exe",3,"OneNote \u2192 CScript \u2014 embedded VBS [T1059.005]"],
["msaccess.exe","cmd.exe",3,"Access \u2192 cmd \u2014 macro execution [T1204.002]"],
["msaccess.exe","powershell.exe",3,"Access \u2192 PS \u2014 macro execution [T1059.001]"],
["mspub.exe","cmd.exe",3,"Publisher \u2192 cmd \u2014 macro execution [T1204.002]"],
["mspub.exe","powershell.exe",3,"Publisher \u2192 PS \u2014 macro execution [T1059.001]"],
["wscript.exe","cmd.exe",2,"WScript \u2192 cmd \u2014 VBS/JS payload stage 2 [T1059.005]"],
["wscript.exe","powershell.exe",2,"WScript \u2192 PS \u2014 VBS to PS stager [T1059.005]"],
["wscript.exe","cscript.exe",1,"WScript \u2192 CScript \u2014 engine switch [T1059.005]"],
["cscript.exe","cmd.exe",2,"CScript \u2192 cmd \u2014 script payload [T1059.005]"],
["cscript.exe","powershell.exe",2,"CScript \u2192 PS \u2014 script stager [T1059.005]"],
["powershell.exe","powershell.exe",1,"PS \u2192 PS \u2014 double-hop/AMSI bypass [T1059.001]"],
["powershell.exe","cmd.exe",0,"PS \u2192 cmd \u2014 may be benign, context-dependent [T1059.003]"],
["powershell.exe","wscript.exe",1,"PS \u2192 WScript \u2014 polyglot/evasion [T1059.005]"],
["powershell.exe","cscript.exe",1,"PS \u2192 CScript \u2014 PS \u2192 CScript exec [T1059.005]"],
["powershell.exe","bash.exe",1,"PS \u2192 bash \u2014 cross-subsystem [T1059.004]"],
["cmd.exe","powershell.exe",1,"cmd \u2192 PS \u2014 common in multi-stage payloads [T1059.001]"],
["cmd.exe","wscript.exe",1,"cmd \u2192 WScript \u2014 script execution [T1059.005]"],
["cmd.exe","cscript.exe",1,"cmd \u2192 CScript \u2014 script execution [T1059.005]"],
["svchost.exe","cmd.exe",2,"svchost \u2192 cmd \u2014 service abuse or lateral [T1569.002]"],
["svchost.exe","powershell.exe",2,"svchost \u2192 PS \u2014 service-based execution [T1569.002]"],
["svchost.exe","wscript.exe",2,"svchost \u2192 WScript \u2014 unusual service behavior [T1059.005]"],
["svchost.exe","cscript.exe",2,"svchost \u2192 CScript \u2014 svchost \u2192 CScript exec [T1059.005]"],
["wmiprvse.exe","cmd.exe",2,"WMIPrvSE \u2192 cmd \u2014 WMI lateral movement [T1047]"],
["wmiprvse.exe","powershell.exe",2,"WMIPrvSE \u2192 PS \u2014 WMI execution [T1047]"],
["searchprotocolhost.exe","cmd.exe",2,"SearchProto \u2192 cmd \u2014 exploit [T1203]"],
["searchindexer.exe","cmd.exe",2,"SearchIdx \u2192 cmd \u2014 exploit [T1203]"],
["csrss.exe","cmd.exe",3,"CSRSS \u2192 cmd \u2014 kernel-mode process injection [T1055]"],
["csrss.exe","powershell.exe",3,"CSRSS \u2192 PS \u2014 critical anomaly [T1055]"],
["smss.exe","cmd.exe",3,"SMSS \u2192 cmd \u2014 critical: bootkit/rootkit [T1055]"],
["smss.exe","powershell.exe",3,"SMSS \u2192 PS \u2014 critical anomaly [T1055]"],
["winlogon.exe","cmd.exe",2,"winlogon \u2192 cmd \u2014 Sticky Keys/a11y backdoor [T1055]"],
["winlogon.exe","powershell.exe",2,"winlogon \u2192 PS \u2014 exploitation [T1055]"],
["spoolsv.exe","cmd.exe",3,"spoolsv \u2192 cmd \u2014 PrintNightmare [T1203]"],
["spoolsv.exe","powershell.exe",3,"spoolsv \u2192 PS \u2014 PrintNightmare [T1203]"],
["spoolsv.exe","net.exe",2,"spoolsv \u2192 net \u2014 PrintNightmare add user [T1203]"],
["dllhost.exe","cmd.exe",2,"dllhost \u2192 cmd \u2014 COM object hijack execution [T1546.015]"],
["dllhost.exe","powershell.exe",2,"dllhost \u2192 PS \u2014 COM hijack [T1546.015]"],
["services.exe","cmd.exe",2,"services \u2192 cmd \u2014 malicious service installed [T1543.003]"],
["services.exe","powershell.exe",2,"services \u2192 PS \u2014 malicious service [T1543.003]"],
["chrome.exe","cmd.exe",2,"Chrome \u2192 cmd \u2014 browser exploit [T1189]"],
["chrome.exe","powershell.exe",3,"Chrome \u2192 PS \u2014 browser exploit [T1189]"],
["msedge.exe","cmd.exe",2,"Edge \u2192 cmd \u2014 browser exploit [T1189]"],
["msedge.exe","powershell.exe",3,"Edge \u2192 PS \u2014 browser exploit [T1189]"],
["firefox.exe","cmd.exe",2,"Firefox \u2192 cmd \u2014 browser exploit [T1189]"],
["firefox.exe","powershell.exe",3,"Firefox \u2192 PS \u2014 browser exploit [T1189]"],
["iexplore.exe","cmd.exe",2,"IE \u2192 cmd \u2014 browser exploit [T1189]"],
["iexplore.exe","powershell.exe",3,"IE \u2192 PS \u2014 browser exploit [T1189]"],
["acrord32.exe","cmd.exe",3,"AcroRd \u2192 cmd \u2014 PDF exploit [T1203]"],
["acrord32.exe","powershell.exe",3,"AcroRd \u2192 PS \u2014 PDF exploit [T1203]"],
["foxitreader.exe","cmd.exe",3,"Foxit \u2192 cmd \u2014 PDF exploit [T1203]"],
["foxitreader.exe","powershell.exe",3,"Foxit \u2192 PS \u2014 PDF exploit [T1203]"],
["w3wp.exe","cmd.exe",3,"IIS \u2192 cmd \u2014 web shell execution [T1190]"],
["w3wp.exe","powershell.exe",3,"IIS \u2192 PS \u2014 web shell [T1190]"],
["w3wp.exe","csc.exe",3,"IIS \u2192 csc \u2014 web shell compilation [T1190]"],
["java.exe","cmd.exe",2,"java \u2192 cmd \u2014 web shell (Tomcat/WebLogic) [T1190]"],
["java.exe","powershell.exe",2,"java \u2192 PS \u2014 web shell [T1190]"],
["java.exe","bash.exe",2,"java \u2192 bash \u2014 web shell (WSL) [T1190]"],
["javaw.exe","cmd.exe",2,"javaw \u2192 cmd \u2014 web shell [T1190]"],
["tomcat.exe","cmd.exe",3,"Tomcat \u2192 cmd \u2014 web shell [T1190]"],
["httpd.exe","cmd.exe",3,"Apache \u2192 cmd \u2014 web shell [T1190]"],
["msexchangemailboxreplication.exe","cmd.exe",3,"ExchMBX \u2192 cmd \u2014 ProxyShell/OWASSRF [T1190]"],
["umworkerprocess.exe","cmd.exe",3,"ExchUM \u2192 cmd \u2014 ProxyLogon exploitation [T1190]"],
["umworkerprocess.exe","powershell.exe",3,"ExchUM \u2192 PS \u2014 exploitation [T1190]"],
["sqlservr.exe","cmd.exe",3,"SQLSrv \u2192 cmd \u2014 xp_cmdshell or SQL injection [T1190]"],
["sqlservr.exe","powershell.exe",3,"SQLSrv \u2192 PS \u2014 SQL injection [T1190]"],
["nginx.exe","cmd.exe",3,"nginx \u2192 cmd \u2014 web shell [T1190]"],
// Defense Evasion / LOLBins
["winword.exe","mshta.exe",3,"Word \u2192 mshta \u2014 HTA proxy execution [T1218.005]"],
["winword.exe","regsvr32.exe",3,"Word \u2192 regsvr32 \u2014 COM scriptlet exec [T1218.010]"],
["winword.exe","rundll32.exe",3,"Word \u2192 rundll32 \u2014 DLL proxy execution [T1218.011]"],
["excel.exe","mshta.exe",3,"Excel \u2192 mshta \u2014 HTA execution [T1218.005]"],
["excel.exe","regsvr32.exe",3,"Excel \u2192 regsvr32 \u2014 Squiblydoo [T1218.010]"],
["excel.exe","rundll32.exe",3,"Excel \u2192 rundll32 \u2014 DLL execution [T1218.011]"],
["powerpnt.exe","mshta.exe",3,"PPT \u2192 mshta \u2014 PPT spawning mshta [T1218.005]"],
["outlook.exe","mshta.exe",3,"Outlook \u2192 mshta \u2014 HTML attachment exec [T1218.005]"],
["outlook.exe","regsvr32.exe",3,"Outlook \u2192 regsvr32 \u2014 Outlook \u2192 regsvr32 exec [T1218.010]"],
["outlook.exe","rundll32.exe",2,"Outlook \u2192 rundll32 \u2014 Outlook \u2192 rundll32 exec [T1218.011]"],
["onenote.exe","mshta.exe",3,"OneNote \u2192 mshta \u2014 embedded HTA [T1218.005]"],
["rundll32.exe","cmd.exe",2,"rundll32 \u2192 cmd \u2014 DLL proxy to shell [T1218.011]"],
["rundll32.exe","powershell.exe",2,"rundll32 \u2192 PS \u2014 DLL proxy exec [T1218.011]"],
["rundll32.exe","cscript.exe",2,"rundll32 \u2192 CScript \u2014 rundll32 \u2192 CScript exec [T1218.011]"],
["rundll32.exe","wscript.exe",2,"rundll32 \u2192 WScript \u2014 rundll32 \u2192 WScript exec [T1218.011]"],
["rundll32.exe","rundll32.exe",2,"rundll32 \u2192 rundll32 \u2014 injection/hollowing [T1218.011]"],
["regsvr32.exe","cmd.exe",2,"regsvr32 \u2192 cmd \u2014 Squiblydoo/COM scriptlet [T1218.010]"],
["regsvr32.exe","powershell.exe",2,"regsvr32 \u2192 PS \u2014 scriptlet exec [T1218.010]"],
["regsvr32.exe","wscript.exe",2,"regsvr32 \u2192 WScript \u2014 regsvr32 \u2192 WScript exec [T1218.010]"],
["regsvr32.exe","cscript.exe",2,"regsvr32 \u2192 CScript \u2014 regsvr32 \u2192 CScript exec [T1218.010]"],
["regsvr32.exe","mshta.exe",2,"regsvr32 \u2192 mshta \u2014 chained proxy exec [T1218.010]"],
["mshta.exe","cmd.exe",2,"mshta \u2192 cmd \u2014 HTA payload execution [T1218.005]"],
["mshta.exe","powershell.exe",3,"mshta \u2192 PS \u2014 HTA to PS cradle [T1218.005]"],
["mshta.exe","wscript.exe",2,"mshta \u2192 WScript \u2014 chained script exec [T1218.005]"],
["mshta.exe","cscript.exe",2,"mshta \u2192 CScript \u2014 mshta \u2192 CScript exec [T1218.005]"],
["mshta.exe","rundll32.exe",2,"mshta \u2192 rundll32 \u2014 chained proxy [T1218.005]"],
["mshta.exe","regsvr32.exe",2,"mshta \u2192 regsvr32 \u2014 chained proxy [T1218.005]"],
["cmstp.exe","cmd.exe",2,"CMSTP \u2192 cmd \u2014 INF-based bypass [T1218.003]"],
["cmstp.exe","powershell.exe",2,"CMSTP \u2192 PS \u2014 INF-based bypass [T1218.003]"],
["msiexec.exe","cmd.exe",2,"msiexec \u2192 cmd \u2014 malicious MSI custom action [T1218.007]"],
["msiexec.exe","powershell.exe",2,"msiexec \u2192 PS \u2014 MSI payload [T1218.007]"],
["msiexec.exe","rundll32.exe",1,"msiexec \u2192 rundll32 \u2014 MSI DLL action [T1218.007]"],
["cmd.exe","msiexec.exe",1,"cmd \u2192 msiexec \u2014 remote MSI install [T1218.007]"],
["installutil.exe","cmd.exe",2,"InstallUtil \u2192 cmd \u2014 .NET payload execution [T1218.004]"],
["msbuild.exe","cmd.exe",2,"MSBuild \u2192 cmd \u2014 inline task execution [T1127.001]"],
["msbuild.exe","powershell.exe",2,"MSBuild \u2192 PS \u2014 inline task [T1127.001]"],
["xwizard.exe","cmd.exe",2,"xwizard \u2192 cmd \u2014 COM object hijack [T1218]"],
["pcalua.exe","cmd.exe",2,"pcalua \u2192 cmd \u2014 proxy exec of cmd [T1218]"],
["pcalua.exe","powershell.exe",2,"pcalua \u2192 PS \u2014 proxy exec of PS [T1218]"],
["pcalua.exe","mshta.exe",2,"pcalua \u2192 mshta \u2014 proxy exec of mshta [T1218]"],
["forfiles.exe","cmd.exe",1,"forfiles \u2192 cmd \u2014 indirect command exec [T1202]"],
["forfiles.exe","powershell.exe",2,"forfiles \u2192 PS \u2014 indirect PS execution [T1202]"],
["wscript.exe","mshta.exe",2,"WScript \u2192 mshta \u2014 chained execution [T1218.005]"],
["wscript.exe","rundll32.exe",2,"WScript \u2192 rundll32 \u2014 DLL load via script [T1218.011]"],
["wscript.exe","regsvr32.exe",2,"WScript \u2192 regsvr32 \u2014 COM registration abuse [T1218.010]"],
["cscript.exe","mshta.exe",2,"CScript \u2192 mshta \u2014 CScript \u2192 mshta exec [T1218.005]"],
["cscript.exe","rundll32.exe",2,"CScript \u2192 rundll32 \u2014 CScript \u2192 rundll32 exec [T1218.011]"],
["powershell.exe","mshta.exe",2,"PS \u2192 mshta \u2014 proxy execution [T1218.005]"],
["powershell.exe","rundll32.exe",2,"PS \u2192 rundll32 \u2014 DLL proxy [T1218.011]"],
["powershell.exe","regsvr32.exe",2,"PS \u2192 regsvr32 \u2014 COM scriptlet [T1218.010]"],
["cmd.exe","mshta.exe",2,"cmd \u2192 mshta \u2014 HTA execution [T1218.005]"],
["cmd.exe","rundll32.exe",1,"cmd \u2192 rundll32 \u2014 DLL exec [T1218.011]"],
["cmd.exe","regsvr32.exe",1,"cmd \u2192 regsvr32 \u2014 COM registration [T1218.010]"],
["cmd.exe","netsh.exe",1,"cmd \u2192 netsh \u2014 firewall manipulation [T1562.004]"],
["svchost.exe","mshta.exe",3,"svchost \u2192 mshta \u2014 service hijack indicator [T1218.005]"],
["svchost.exe","rundll32.exe",1,"svchost \u2192 rundll32 \u2014 DLL service execution [T1218.011]"],
["svchost.exe","regsvr32.exe",2,"svchost \u2192 regsvr32 \u2014 svchost \u2192 regsvr32 exec [T1218.010]"],
["wmiprvse.exe","mshta.exe",3,"WMIPrvSE \u2192 mshta \u2014 WMI-based proxy exec [T1218.005]"],
["wmiprvse.exe","rundll32.exe",2,"WMIPrvSE \u2192 rundll32 \u2014 WMI \u2192 rundll32 exec [T1218.011]"],
["wmiprvse.exe","regsvr32.exe",2,"WMIPrvSE \u2192 regsvr32 \u2014 WMI \u2192 regsvr32 exec [T1218.010]"],
["werfault.exe","cmd.exe",2,"WerFault \u2192 cmd \u2014 crash handler abuse/injection [T1036]"],
["werfault.exe","powershell.exe",2,"WerFault \u2192 PS \u2014 process injection indicator [T1036]"],
["spoolsv.exe","rundll32.exe",2,"spoolsv \u2192 rundll32 \u2014 spooler exploit [T1203]"],
["cmd.exe","wevtutil.exe",3,"cmd \u2192 wevtutil \u2014 event log clearing/tampering [T1070.001]"],
["powershell.exe","wevtutil.exe",3,"PS \u2192 wevtutil \u2014 event log clearing [T1070.001]"],
["cmd.exe","fsutil.exe",1,"cmd \u2192 fsutil \u2014 timestomping/USN journal del [T1070]"],
["powershell.exe","fsutil.exe",1,"PS \u2192 fsutil \u2014 artifact manipulation [T1070]"],
["powershell.exe","netsh.exe",1,"PS \u2192 netsh \u2014 firewall modification [T1562.004]"],
["powershell.exe","mpcmdrun.exe",1,"PS \u2192 MpCmdRun \u2014 Defender manipulation [T1562.001]"],
["cmd.exe","taskkill.exe",1,"cmd \u2192 taskkill \u2014 process kill (AV/EDR) [T1562.001]"],
["powershell.exe","taskkill.exe",1,"PS \u2192 taskkill \u2014 security tool termination [T1562.001]"],
["cmd.exe","fltmc.exe",3,"cmd \u2192 fltMC \u2014 minifilter unload (EDR bypass) [T1562.001]"],
["powershell.exe","fltmc.exe",3,"PS \u2192 fltMC \u2014 minifilter/driver unload [T1562.001]"],
["bash.exe","cmd.exe",1,"bash \u2192 cmd \u2014 cross-subsystem execution [T1202]"],
["wsl.exe","cmd.exe",1,"WSL \u2192 cmd \u2014 cross-subsystem [T1202]"],
["wsl.exe","powershell.exe",1,"WSL \u2192 PS \u2014 cross-subsystem [T1202]"],
// C2 / Download / RATs
["winword.exe","certutil.exe",3,"Word \u2192 certutil \u2014 download cradle [T1105]"],
["winword.exe","bitsadmin.exe",3,"Word \u2192 bitsadmin \u2014 BITS download [T1197]"],
["excel.exe","certutil.exe",3,"Excel \u2192 certutil \u2014 download cradle [T1105]"],
["rundll32.exe","certutil.exe",2,"rundll32 \u2192 certutil \u2014 staged download [T1105]"],
["cmd.exe","certutil.exe",2,"cmd \u2192 certutil \u2014 LOLBin download/decode [T1105]"],
["powershell.exe","certutil.exe",2,"PS \u2192 certutil \u2014 download/decode fallback [T1105]"],
["cmd.exe","bitsadmin.exe",2,"cmd \u2192 bitsadmin \u2014 BITS job download [T1197]"],
["powershell.exe","bitsadmin.exe",2,"PS \u2192 bitsadmin \u2014 BITS download [T1197]"],
["wscript.exe","certutil.exe",2,"WScript \u2192 certutil \u2014 download stage [T1105]"],
["svchost.exe","certutil.exe",2,"svchost \u2192 certutil \u2014 download via service [T1105]"],
["wmiprvse.exe","certutil.exe",2,"WMIPrvSE \u2192 certutil \u2014 WMI-staged download [T1105]"],
["cmd.exe","wget.exe",1,"cmd \u2192 wget \u2014 file download [T1105]"],
["anydesk.exe","cmd.exe",2,"AnyDesk \u2192 cmd \u2014 remote access tool abuse [T1219]"],
["anydesk.exe","powershell.exe",2,"AnyDesk \u2192 PS \u2014 RAT abuse [T1219]"],
["teamviewer.exe","cmd.exe",2,"TeamViewer \u2192 cmd \u2014 remote tool abuse [T1219]"],
["teamviewer.exe","powershell.exe",2,"TeamViewer \u2192 PS \u2014 TeamViewer \u2192 PS exec [T1219]"],
["teamviewer_service.exe","cmd.exe",2,"TeamViewer service \u2192 cmd \u2014 remote tool abuse [T1219]"],
["teamviewer_service.exe","powershell.exe",2,"TeamViewer service \u2192 PS \u2014 remote tool abuse [T1219]"],
["screenconnect.clientservice.exe","cmd.exe",2,"ScreenConnect \u2192 cmd \u2014 RAT abuse (ransomware) [T1219]"],
["screenconnect.clientservice.exe","powershell.exe",2,"ScreenConnect \u2192 PS \u2014 ScreenConnect \u2192 PS exec [T1219]"],
["screenconnect.windowsclient.exe","cmd.exe",2,"SCClient \u2192 cmd \u2014 SCClient \u2192 cmd exec [T1219]"],
["screenconnect.windowsclient.exe","powershell.exe",2,"SCClient \u2192 PS \u2014 SCClient \u2192 PS exec [T1219]"],
["ateraagent.exe","cmd.exe",2,"Atera \u2192 cmd \u2014 RMM abuse [T1219]"],
["ateraagent.exe","powershell.exe",2,"Atera \u2192 PS \u2014 Atera RMM \u2192 PS exec [T1219]"],
["splashtop.exe","cmd.exe",2,"Splashtop \u2192 cmd \u2014 Splashtop \u2192 cmd exec [T1219]"],
["splashtop.exe","powershell.exe",2,"Splashtop \u2192 PS \u2014 Splashtop \u2192 PS exec [T1219]"],
["cmd.exe","ngrok.exe",3,"cmd \u2192 ngrok \u2014 reverse tunnel for C2 [T1572]"],
["powershell.exe","ngrok.exe",3,"PS \u2192 ngrok \u2014 tunnel establishment [T1572]"],
["cmd.exe","chisel.exe",3,"cmd \u2192 Chisel \u2014 SOCKS proxy tunnel [T1572]"],
["powershell.exe","chisel.exe",3,"PS \u2192 Chisel \u2014 proxy tunnel [T1572]"],
["cmd.exe","plink.exe",2,"cmd \u2192 plink \u2014 SSH tunnel (PuTTY) [T1572]"],
["powershell.exe","plink.exe",2,"PS \u2192 plink \u2014 SSH tunnel [T1572]"],
["w3wp.exe","certutil.exe",3,"IIS \u2192 certutil \u2014 web shell download [T1190]"],
// Persistence
["winword.exe","schtasks.exe",2,"Word \u2192 schtasks \u2014 persistence via macro [T1053.005]"],
["taskeng.exe","cmd.exe",1,"TaskEng \u2192 cmd \u2014 scheduled task execution [T1053.005]"],
["taskeng.exe","powershell.exe",1,"TaskEng \u2192 PS \u2014 Task Scheduler spawning [T1053.005]"],
["taskhostw.exe","cmd.exe",1,"TaskHost \u2192 cmd \u2014 scheduled task (Win10+) [T1053.005]"],
["taskhostw.exe","powershell.exe",1,"TaskHost \u2192 PS \u2014 scheduled task [T1053.005]"],
["cmd.exe","schtasks.exe",1,"cmd \u2192 schtasks \u2014 scheduled task creation [T1053.005]"],
["powershell.exe","schtasks.exe",1,"PS \u2192 schtasks \u2014 scheduled task creation [T1053.005]"],
["rundll32.exe","schtasks.exe",2,"rundll32 \u2192 schtasks \u2014 DLL-based persistence [T1053.005]"],
["mshta.exe","schtasks.exe",2,"mshta \u2192 schtasks \u2014 HTA persistence install [T1053.005]"],
["cmd.exe","reg.exe",1,"cmd \u2192 reg \u2014 Run key persistence [T1547.001]"],
["powershell.exe","reg.exe",1,"PS \u2192 reg \u2014 Run key modification [T1547.001]"],
["cmd.exe","sc.exe",1,"cmd \u2192 sc \u2014 service creation/modification [T1543.003]"],
["powershell.exe","sc.exe",1,"PS \u2192 sc \u2014 service manipulation [T1543.003]"],
["cmd.exe","wmic.exe",1,"cmd \u2192 wmic \u2014 WMI event subscription [T1546.003]"],
["powershell.exe","wmic.exe",1,"PS \u2192 wmic \u2014 WMI persistence [T1546.003]"],
["cmd.exe","xcopy.exe",0,"cmd \u2192 xcopy \u2014 startup folder persistence [T1547.001]"],
["cmd.exe","copy.exe",0,"cmd \u2192 copy \u2014 startup persistence [T1547.001]"],
["winlogon.exe","sethc.exe",3,"winlogon \u2192 sethc \u2014 Sticky Keys backdoor check [T1546.008]"],
["sethc.exe","cmd.exe",3,"sethc \u2192 cmd \u2014 backdoor active [T1546.008]"],
["utilman.exe","cmd.exe",3,"utilman \u2192 cmd \u2014 accessibility backdoor [T1546.008]"],
["osk.exe","cmd.exe",3,"osk \u2192 cmd \u2014 accessibility backdoor [T1546.008]"],
["narrator.exe","cmd.exe",3,"narrator \u2192 cmd \u2014 accessibility backdoor [T1546.008]"],
["magnify.exe","cmd.exe",3,"magnify \u2192 cmd \u2014 accessibility backdoor [T1546.008]"],
["displayswitch.exe","cmd.exe",3,"dispswitch \u2192 cmd \u2014 accessibility backdoor [T1546.008]"],
["atbroker.exe","cmd.exe",3,"ATBroker \u2192 cmd \u2014 accessibility backdoor [T1546.008]"],
// Discovery / Recon
["rundll32.exe","net.exe",1,"rundll32 \u2192 net \u2014 post-exploitation recon [T1087.002]"],
["powershell.exe","whoami.exe",1,"PS \u2192 whoami \u2014 user context enumeration [T1033]"],
["cmd.exe","whoami.exe",1,"cmd \u2192 whoami \u2014 user context enumeration [T1033]"],
["powershell.exe","systeminfo.exe",1,"PS \u2192 systeminfo \u2014 system fingerprinting [T1082]"],
["cmd.exe","systeminfo.exe",1,"cmd \u2192 systeminfo \u2014 system fingerprinting [T1082]"],
["powershell.exe","hostname.exe",0,"PS \u2192 hostname \u2014 hostname discovery [T1082]"],
["cmd.exe","hostname.exe",0,"cmd \u2192 hostname \u2014 hostname discovery [T1082]"],
["powershell.exe","nltest.exe",1,"PS \u2192 nltest \u2014 domain trust enumeration [T1482]"],
["cmd.exe","nltest.exe",1,"cmd \u2192 nltest \u2014 domain trust enumeration [T1482]"],
["powershell.exe","dsquery.exe",1,"PS \u2192 dsquery \u2014 AD object enumeration [T1018]"],
["cmd.exe","dsquery.exe",1,"cmd \u2192 dsquery \u2014 AD enumeration [T1018]"],
["powershell.exe","dsget.exe",1,"PS \u2192 dsget \u2014 AD attribute query [T1087.002]"],
["powershell.exe","csvde.exe",1,"PS \u2192 csvde \u2014 bulk AD export [T1087.002]"],
["powershell.exe","ldifde.exe",1,"PS \u2192 ldifde \u2014 LDAP data export [T1087.002]"],
["cmd.exe","csvde.exe",1,"cmd \u2192 csvde \u2014 bulk AD export [T1087.002]"],
["powershell.exe","net.exe",1,"PS \u2192 net \u2014 domain/local account enum [T1087.002]"],
["cmd.exe","net.exe",1,"cmd \u2192 net \u2014 domain/local account enum [T1087.002]"],
["powershell.exe","net1.exe",1,"PS \u2192 net1 \u2014 net.exe proxy [T1087.002]"],
["cmd.exe","net1.exe",1,"cmd \u2192 net1 \u2014 net.exe proxy [T1087.002]"],
["powershell.exe","ipconfig.exe",0,"PS \u2192 ipconfig \u2014 network config discovery [T1016]"],
["cmd.exe","ipconfig.exe",0,"cmd \u2192 ipconfig \u2014 network config [T1016]"],
["powershell.exe","arp.exe",0,"PS \u2192 arp \u2014 ARP table discovery [T1016]"],
["cmd.exe","arp.exe",0,"cmd \u2192 arp \u2014 ARP table discovery [T1016]"],
["powershell.exe","nslookup.exe",0,"PS \u2192 nslookup \u2014 DNS recon [T1018]"],
["cmd.exe","nslookup.exe",0,"cmd \u2192 nslookup \u2014 DNS recon [T1018]"],
["powershell.exe","netstat.exe",0,"PS \u2192 netstat \u2014 network connections [T1049]"],
["cmd.exe","netstat.exe",0,"cmd \u2192 netstat \u2014 network connections [T1049]"],
["powershell.exe","route.exe",0,"PS \u2192 route \u2014 routing table [T1016]"],
["cmd.exe","route.exe",0,"cmd \u2192 route \u2014 routing table [T1016]"],
["powershell.exe","nbtstat.exe",0,"PS \u2192 nbtstat \u2014 NetBIOS discovery [T1016]"],
["cmd.exe","tracert.exe",0,"cmd \u2192 tracert \u2014 route tracing [T1016]"],
["cmd.exe","pathping.exe",0,"cmd \u2192 pathping \u2014 route tracing [T1016]"],
["powershell.exe","tasklist.exe",0,"PS \u2192 tasklist \u2014 process enumeration [T1057]"],
["cmd.exe","tasklist.exe",0,"cmd \u2192 tasklist \u2014 process enumeration [T1057]"],
["powershell.exe","qprocess.exe",0,"PS \u2192 qprocess \u2014 terminal svc process list [T1057]"],
["powershell.exe","sc.exe",0,"PS \u2192 sc \u2014 service enumeration [T1007]"],
["cmd.exe","sc.exe",0,"cmd \u2192 sc \u2014 service enumeration [T1007]"],
["powershell.exe","wmic.exe",1,"PS \u2192 wmic \u2014 WMI queries [T1047]"],
["cmd.exe","wmic.exe",1,"cmd \u2192 wmic \u2014 WMI queries [T1047]"],
["powershell.exe","netsh.exe",1,"PS \u2192 netsh \u2014 firewall/security enum [T1518.001]"],
["powershell.exe","net.exe",1,"PS \u2192 net \u2014 network share discovery [T1135]"],
["cmd.exe","net.exe",1,"cmd \u2192 net \u2014 network share discovery [T1135]"],
["powershell.exe","icacls.exe",0,"PS \u2192 icacls \u2014 permission enumeration [T1083]"],
["cmd.exe","icacls.exe",0,"cmd \u2192 icacls \u2014 permission enumeration [T1083]"],
["cmd.exe","accesschk.exe",1,"cmd \u2192 accesschk \u2014 Sysinternals permission check [T1083]"],
["powershell.exe","adfind.exe",3,"PS \u2192 AdFind \u2014 bulk AD enum (ransomware) [T1018]"],
["cmd.exe","adfind.exe",3,"cmd \u2192 AdFind \u2014 bulk AD enumeration [T1018]"],
["powershell.exe","bloodhound.exe",3,"PS \u2192 BloodHound \u2014 AD attack path mapping [T1087.002]"],
["cmd.exe","sharphound.exe",3,"cmd \u2192 SharpHound \u2014 BloodHound data collector [T1087.002]"],
["powershell.exe","sharphound.exe",3,"PS \u2192 SharpHound \u2014 AD collector [T1087.002]"],
["powershell.exe","seatbelt.exe",2,"PS \u2192 Seatbelt \u2014 GhostPack host survey [T1082]"],
["cmd.exe","seatbelt.exe",2,"cmd \u2192 Seatbelt \u2014 GhostPack host survey [T1082]"],
["svchost.exe","whoami.exe",2,"svchost \u2192 whoami \u2014 post-exploitation via service [T1033]"],
["svchost.exe","net.exe",1,"svchost \u2192 net \u2014 recon via service context [T1087.002]"],
["w3wp.exe","whoami.exe",3,"IIS \u2192 whoami \u2014 web shell recon [T1190]"],
["w3wp.exe","net.exe",3,"IIS \u2192 net \u2014 web shell enumeration [T1190]"],
// Credential Access
["powershell.exe","rubeus.exe",3,"PS \u2192 Rubeus \u2014 Kerberos attack tool [T1558.003]"],
["cmd.exe","rubeus.exe",3,"cmd \u2192 Rubeus \u2014 Kerberos attack tool [T1558.003]"],
["lsass.exe","cmd.exe",3,"LSASS \u2192 cmd \u2014 credential dumping/injection [T1003.001]"],
["lsass.exe","powershell.exe",3,"LSASS \u2192 PS \u2014 process injection into LSASS [T1003.001]"],
["lsass.exe","rundll32.exe",3,"LSASS \u2192 rundll32 \u2014 skeleton key/SSP injection [T1003.001]"],
["cmd.exe","procdump.exe",3,"cmd \u2192 ProcDump \u2014 LSASS memory dump [T1003.001]"],
["powershell.exe","procdump.exe",3,"PS \u2192 ProcDump \u2014 LSASS dump [T1003.001]"],
["cmd.exe","mimikatz.exe",3,"cmd \u2192 Mimikatz \u2014 credential dumping [T1003.001]"],
["powershell.exe","mimikatz.exe",3,"PS \u2192 Mimikatz \u2014 credential dumping [T1003.001]"],
["cmd.exe","sekurlsa.exe",3,"cmd \u2192 sekurlsa \u2014 credential extraction [T1003.001]"],
["cmd.exe","lazagne.exe",3,"cmd \u2192 LaZagne \u2014 credential recovery from apps [T1555]"],
["powershell.exe","lazagne.exe",3,"PS \u2192 LaZagne \u2014 credential harvesting [T1555]"],
["cmd.exe","vssadmin.exe",2,"cmd \u2192 vssadmin \u2014 shadow copy for NTDS.dit [T1003.003]"],
["powershell.exe","vssadmin.exe",2,"PS \u2192 vssadmin \u2014 shadow copy access [T1003.003]"],
["cmd.exe","wbadmin.exe",2,"cmd \u2192 wbadmin \u2014 backup-based cred extraction [T1003.003]"],
["cmd.exe","diskshadow.exe",2,"cmd \u2192 diskshadow \u2014 NTDS.dit shadow copy [T1003.003]"],
["cmd.exe","ntdsutil.exe",3,"cmd \u2192 ntdsutil \u2014 AD database extraction (IFM) [T1003.003]"],
["powershell.exe","ntdsutil.exe",3,"PS \u2192 ntdsutil \u2014 NTDS.dit dump [T1003.003]"],
["cmd.exe","reg.exe",1,"cmd \u2192 reg \u2014 SAM/SECURITY/SYSTEM hive export [T1003.002]"],
["powershell.exe","reg.exe",1,"PS \u2192 reg \u2014 registry hive export [T1003.002]"],
["cmd.exe","klist.exe",0,"cmd \u2192 klist \u2014 Kerberos ticket inspection [T1558]"],
["powershell.exe","klist.exe",0,"PS \u2192 klist \u2014 Kerberos ticket enumeration [T1558]"],
["cmd.exe","esentutl.exe",2,"cmd \u2192 esentutl \u2014 ESE database extraction [T1003.003]"],
["powershell.exe","esentutl.exe",2,"PS \u2192 esentutl \u2014 locked file copy [T1003.003]"],
// Lateral Movement
["psexesvc.exe","cmd.exe",2,"PsExecSvc \u2192 cmd \u2014 remote execution (target side) [T1570]"],
["psexesvc.exe","powershell.exe",2,"PsExecSvc \u2192 PS \u2014 PsExec svc \u2192 PS exec [T1570]"],
["services.exe","psexesvc.exe",2,"services \u2192 PsExecSvc \u2014 lateral movement inbound [T1570]"],
["cmd.exe","psexec.exe",2,"cmd \u2192 PsExec \u2014 lateral movement initiated [T1570]"],
["powershell.exe","psexec.exe",2,"PS \u2192 PsExec \u2014 remote execution [T1570]"],
["wsmprovhost.exe","cmd.exe",2,"WinRM \u2192 cmd \u2014 remote PowerShell session \u2192 shell [T1021.006]"],
["wsmprovhost.exe","powershell.exe",2,"WinRM \u2192 PS \u2014 remote PS session [T1021.006]"],
["wsmprovhost.exe","whoami.exe",2,"WinRM \u2192 whoami \u2014 remote session recon [T1021.006]"],
["wsmprovhost.exe","net.exe",2,"WinRM \u2192 net \u2014 remote session enumeration [T1021.006]"],
["mmc.exe","cmd.exe",2,"MMC \u2192 cmd \u2014 DCOM lateral movement [T1021.003]"],
["mmc.exe","powershell.exe",2,"MMC \u2192 PS \u2014 DCOM execution [T1021.003]"],
["sshd.exe","cmd.exe",1,"SSHD \u2192 cmd \u2014 SSH-based remote access [T1021.004]"],
["sshd.exe","powershell.exe",1,"SSHD \u2192 PS \u2014 SSH remote execution [T1021.004]"],
["cmd.exe","gpupdate.exe",1,"cmd \u2192 gpupdate \u2014 GPO-based deployment [T1484.001]"],
["powershell.exe","gpupdate.exe",1,"PS \u2192 gpupdate \u2014 GPO-based deployment [T1484.001]"],
// Impact / Ransomware
["cmd.exe","vssadmin.exe",3,"cmd \u2192 vssadmin \u2014 shadow copy deletion [T1490]"],
["powershell.exe","vssadmin.exe",3,"PS \u2192 vssadmin \u2014 shadow copy deletion [T1490]"],
["cmd.exe","wmic.exe",3,"cmd \u2192 wmic \u2014 ransomware indicator [T1490]"],
["cmd.exe","bcdedit.exe",3,"cmd \u2192 bcdedit \u2014 boot config modification [T1490]"],
["powershell.exe","bcdedit.exe",3,"PS \u2192 bcdedit \u2014 recovery disable [T1490]"],
["cmd.exe","cipher.exe",2,"cmd \u2192 cipher \u2014 secure wipe/ransomware [T1486]"],
["powershell.exe","cipher.exe",2,"PS \u2192 cipher \u2014 wipe free space [T1486]"],
["cmd.exe","wbadmin.exe",3,"cmd \u2192 wbadmin \u2014 backup catalog deletion [T1490]"],
["powershell.exe","wbadmin.exe",3,"PS \u2192 wbadmin \u2014 backup deletion [T1490]"],
["cmd.exe","psexec.exe",3,"cmd \u2192 PsExec \u2014 mass ransomware deployment [T1486]"],
["powershell.exe","psexec.exe",3,"PS \u2192 PsExec \u2014 ransomware distribution [T1486]"],
// Collection / Staging
["cmd.exe","rar.exe",2,"cmd \u2192 rar \u2014 archive creation for exfiltration [T1560.001]"],
["powershell.exe","rar.exe",2,"PS \u2192 rar \u2014 data staging [T1560.001]"],
["cmd.exe","7z.exe",1,"cmd \u2192 7z \u2014 archive creation [T1560.001]"],
["powershell.exe","7z.exe",1,"PS \u2192 7z \u2014 data staging [T1560.001]"],
["cmd.exe","7za.exe",2,"cmd \u2192 7za \u2014 common in ransomware toolkits [T1560.001]"],
["cmd.exe","makecab.exe",1,"cmd \u2192 makecab \u2014 LOLBin archive creation [T1560.001]"],
["powershell.exe","makecab.exe",1,"PS \u2192 makecab \u2014 LOLBin archive [T1560.001]"],
// Exfiltration
["cmd.exe","curl.exe",1,"cmd \u2192 curl \u2014 data exfiltration [T1048]"],
["powershell.exe","curl.exe",1,"PS \u2192 curl \u2014 data transfer [T1048]"],
["cmd.exe","ftp.exe",1,"cmd \u2192 ftp \u2014 FTP data transfer [T1048.003]"],
["powershell.exe","ftp.exe",1,"PS \u2192 ftp \u2014 data exfiltration [T1048.003]"],
["cmd.exe","scp.exe",1,"cmd \u2192 scp \u2014 SCP file transfer [T1048]"],
["cmd.exe","sftp.exe",1,"cmd \u2192 sftp \u2014 SFTP transfer [T1048]"],
["cmd.exe","rclone.exe",3,"cmd \u2192 rclone \u2014 cloud exfiltration [T1567.002]"],
["powershell.exe","rclone.exe",3,"PS \u2192 rclone \u2014 cloud storage exfil [T1567.002]"],
["cmd.exe","megasync.exe",3,"cmd \u2192 MEGASync \u2014 cloud exfiltration [T1567.002]"],
["cmd.exe","megacmd.exe",3,"cmd \u2192 MEGAcmd \u2014 cloud exfil CLI [T1567.002]"],
["powershell.exe","megacmd.exe",3,"PS \u2192 MEGAcmd \u2014 cloud exfil [T1567.002]"],
];

// Escalations that require the COMMAND LINE, keyed by the child process base name.
//
// A parent->child pair alone cannot distinguish `vssadmin list shadows` (a backup
// script) from `vssadmin delete shadows` (ransomware), or `wmic os get caption`
// from `wmic shadowcopy delete`. CHAIN_RULES describes both readings of those
// pairs, and the map used to resolve duplicates by taking the HIGHEST severity —
// so the destructive interpretation applied unconditionally and every `wmic os
// get`, `vssadmin list`, `bcdedit /enum` and `wevtutil qe` from a shell was
// reported as a critical ransomware indicator.
//
// Now the bare pair is capped at low and only these patterns raise it.
export const CHAIN_ARG_ESCALATIONS = new Map(Object.entries({
  vssadmin: [
    { rx: /\bdelete\s+shadows?\b|\bresize\s+shadowstorage\b/i, level: 3, reason: "shadow copy deletion", techniques: ["T1490"] },
    { rx: /\bcreate\s+shadow\b/i, level: 2, reason: "shadow copy creation (NTDS.dit / hive access)", techniques: ["T1003.003"] },
  ],
  wmic: [
    { rx: /\bshadowcopy\b[\s\S]*\bdelete\b/i, level: 3, reason: "shadow copy deletion via WMI", techniques: ["T1490"] },
    { rx: /\/node\s*:|\bprocess\b[\s\S]*\bcall\b[\s\S]*\bcreate\b/i, level: 2, reason: "remote/spawning WMI execution", techniques: ["T1047"] },
    { rx: /\b__eventfilter\b|\b__filtertoconsumerbinding\b|\bcommandlineeventconsumer\b/i, level: 3, reason: "WMI event subscription persistence", techniques: ["T1546.003"] },
  ],
  bcdedit: [
    { rx: /\b(safeboot|recoveryenabled|bootstatuspolicy|ignoreallfailures)\b/i, level: 3, reason: "boot/recovery configuration tampering", techniques: ["T1490"] },
  ],
  wevtutil: [
    { rx: /(^|\s)(cl|clear-log)(\s|$)|\bsl\b[\s\S]*\/e\s*:\s*false/i, level: 3, reason: "event log clearing/disabling", techniques: ["T1070.001"] },
  ],
  wbadmin: [
    { rx: /\bdelete\s+(catalog|systemstatebackup|backup)\b/i, level: 3, reason: "backup catalog deletion", techniques: ["T1490"] },
    { rx: /\bstart\s+recovery\b|\bget\s+versions\b/i, level: 2, reason: "backup-based credential extraction", techniques: ["T1003.003"] },
  ],
  cipher: [
    { rx: /\s\/w\b/i, level: 2, reason: "free-space wipe", techniques: ["T1485"] },
  ],
  reg: [
    { rx: /\bsave\b[\s\S]*\bhklm\\(sam|security|system)\b/i, level: 3, reason: "SAM/SECURITY/SYSTEM hive export", techniques: ["T1003.002"] },
    { rx: /\badd\b[\s\S]*\\currentversion\\run/i, level: 2, reason: "Run key persistence", techniques: ["T1547.001"] },
  ],
  sc: [
    { rx: /\b(create|config|failure)\b/i, level: 1, reason: "service creation/modification", techniques: ["T1543.003"] },
  ],
  psexec: [
    { rx: /\\\\[^\s\\]+|@[^\s]+\.txt|\/accepteula[\s\S]*\\\\/i, level: 3, reason: "remote execution across hosts", techniques: ["T1570"] },
  ],
  netsh: [
    { rx: /\b(firewall|advfirewall)\b[\s\S]*\b(add|set|delete)\b|\bportproxy\b/i, level: 2, reason: "firewall/portproxy modification", techniques: ["T1562.004"] },
  ],
}));

// Build lookup map keyed by "parent:child" (sans .exe).
// Technique IDs extracted from reason text at build time (first-class, no regex fallback needed)
export const CHAIN_RULE_MAP = new Map();
for (const [p, c, sev, desc] of CHAIN_RULES) {
  const key = p.replace(/\.exe$/i, "") + ":" + c.replace(/\.exe$/i, "");
  const techniques = desc.match(/\bT\d{4}(?:\.\d{3})?\b/g) || [];
  const reason = desc.replace(/\s*\[T\d{4}(?:\.\d{3})?]/g, "").trim();
  const ex = CHAIN_RULE_MAP.get(key);
  // LOWEST severity wins for duplicates. A duplicate key means the same pair has
  // several readings; without the arguments we can only assert the mildest one.
  if (!ex || sev < ex.level) CHAIN_RULE_MAP.set(key, { level: sev, reason, techniques });
}
// Cap the bare (argument-free) form of every escalatable pair at low, so the pair
// itself is a lead and the arguments decide the severity.
for (const entry of CHAIN_RULE_MAP.entries()) {
  const [key, val] = entry;
  const child = key.slice(key.indexOf(":") + 1);
  if (CHAIN_ARG_ESCALATIONS.has(child) && val.level >= 1) {
    // Neutralise the wording and drop the ATT&CK tag as well: the retained reason
    // described the destructive reading, so leaving it (or T1490) on `bcdedit /enum`
    // would just move the false positive from the severity column to the text and
    // the technique matrix.
    const pair = val.reason.split(" \u2014 ")[0];
    CHAIN_RULE_MAP.set(key, { level: 1, reason: `${pair} \u2014 no notable arguments`, techniques: [] });
  }
}

/**
 * Resolve a parent->child chain rule against the child's command line.
 * Returns null when the pair is not a known chain.
 */
export function resolveChainRule(key, cmd) {
  const base = CHAIN_RULE_MAP.get(key);
  if (!base) return null;
  const child = key.slice(key.indexOf(":") + 1);
  const escalations = CHAIN_ARG_ESCALATIONS.get(child);
  if (escalations && cmd) {
    let best = null;
    for (const e of escalations) {
      if (!e.rx.test(cmd)) continue;
      if (!best || e.level > best.level) best = e;
    }
    if (best && best.level > base.level) {
      return { level: best.level, reason: `${base.reason.split(" \u2014 ")[0]} \u2014 ${best.reason}`, techniques: best.techniques, escalated: true };
    }
    if (best && best.level === base.level && best.techniques.length > 0) {
      return { level: base.level, reason: `${base.reason.split(" \u2014 ")[0]} \u2014 ${best.reason}`, techniques: best.techniques, escalated: true };
    }
  }
  return base;
}

// Standalone detection patterns — command-line, path, and process-name based (not parent→child)

// THE canonical "a standard user can write here without elevation" test.
//
// Six near-identical variants of this used to live across process-inspector.js,
// process-inspector-pipeline.js and this file, and they disagreed in ways that
// changed verdicts: only some included \Users\ (so a payload on the Desktop or in
// Documents was not a suspicious path), none of the detection-side ones included
// \ProgramData\ (one of the most common malware staging directories, writable by
// BUILTIN\Users on a default install), and only some included the recycle bin.
// Forward slashes are accepted because some exporters normalise paths that way.
export const USER_WRITABLE_PATH = /[\\/](users|temp|tmp|appdata|downloads|public|perflogs|programdata|\$recycle\.bin|recycler)[\\/]/i;

// Locations that are user-writable BY DESIGN because that is where per-user and
// per-vendor installs go. Broadening USER_WRITABLE_PATH above would otherwise turn
// every Teams/Slack/VS Code/Chrome-updater process into a suspicious-path finding.
export const BENIGN_INSTALL_PATH = /[\\/](appdata[\\/]local[\\/](programs|microsoft[\\/](teams|onedrive|edgeupdate|edgewebview)|google[\\/]update|slack|discord|postman|jetbrains|github ?desktop)|programdata[\\/](microsoft|package cache|chocolatey|docker|anaconda3?|nvidia|intel|dell|hp|lenovo|amazon|checkpoint|sophos|sentinelone|crowdstrike|mcafee|symantec|trendmicro|kaspersky|eset|bitdefender|webroot|carbonblack|cylance|paloaltonetworks|cortex))[\\/]/i;

// Back-compat alias — SUS_PATHS is imported by name in several rule modules.
export const SUS_PATHS = USER_WRITABLE_PATH;
// Known-safe Windows processes that legitimately run from \Temp, \AppData, etc.
export const SAFE_PROCS = /^(mpcmdrun|msmpeng|dismhost|monagentcore|monagenthost|monagentmanager|monagentlauncher|metricsextension\.native|cleanmgr|tiworker|wuauclt|setup|msiexec|drvinst|trustedinstaller|taskhostw|backgroundtaskhost|runtimebroker|searchprotocolhost|searchindexer|searchfilterhost|microsoftedgeupdate|googleupdate|onedrive|onedriveupdater|wermgr|werfault|compattelrunner)(\.exe)?$/i;
export const ENCODED_PS = /\s+(-e\s|-enc\s|-encodedcommand\s|-en\s|-ec\s)/i;
export const CRED_DUMP_CMD = /(comsvcs\.dll|sekurlsa|lsadump|procdump.*lsass|mimikatz|pypykatz|nanodump|dcsync|drsuapi)/i;
export const NTDS_EXTRACT = /(ntdsutil.*ifm|wbadmin.*ntds|secretsdump|ntds\.dit)/i;
// Tools capable of producing a process memory dump. Name alone is NOT evidence of
// credential theft — procdump, ProcessHacker and createdump are ordinary developer
// and support tools — so pi-6 requires an lsass target (command line or an observed
// EID 10 handle) before it scores. The catalogue is wide precisely because the rule
// that consumes it is now specific.
export const LSASS_TOOLS = /^(processhacker|systeminformer|procdump|procdump64|sqldumper|avdump|avdump32|avdump64|handlekatz|nanodump|createdump|rdrleakdiag|dumpert|procexp|procexp64|werfaultsecure|minidumpwritedump|outflanknanodump|lsassy|safetykatz|sharpdump|physmem2profit|dumpminitool)(\.exe)?$/i;
// Command-line evidence that a dumper is aimed at LSASS specifically.
export const LSASS_TARGET_CMD = /(\blsass(\.exe)?\b|\blsass_?dump\b|\b-ma\s+lsass|\bprocessid\s*[:=]?\s*\d+\s+.*lsass|\/pn\s*:?\s*lsass)/i;
export const ACCOUNT_MANIP = /net\s+(user|group|localgroup)\s+.*(\/add|\/domain\s+\/add)/i;
export const DEFENSE_EVASION = /(vssadmin.*delete|wevtutil\s+cl|bcdedit.*safeboot|bcdedit.*recoveryenabled)/i;
export const NETWORK_SCANNERS = /^(netscan|netscan64|advanced_ip_scanner|rustscan|masscan|angry_ip_scanner|nbtscan)(\.exe)?$/i;
export const AD_RECON_TOOLS = /^(adfind|sharphound|bloodhound|sharpview|seatbelt|rubeus|certify|certipy)(\.exe)?$/i;
// RMM_TOOLS / EXFIL_TOOLS / TUNNEL_TOOLS are derived from the canonical alias
// table (Finding #5). Adding a new tool variant means editing one place — the
// previous hand-maintained regexes drifted from chain rules and the PI allowlist
// and silently missed names like screenconnect.clientservice.exe and ateraagent.exe.
import { buildCategoryRegex } from "./detection-rules/tool-aliases.js";
export { TOOL_ENTRIES, TOOL_BY_ALIAS, lookupTool, _toolAliasKey } from "./detection-rules/tool-aliases.js";
export const RMM_TOOLS = buildCategoryRegex("rmm");
export const EXFIL_TOOLS = buildCategoryRegex("exfil");
export const TUNNEL_TOOLS = buildCategoryRegex("tunnel");
// Password-protected archive creation is the strong exfil-staging signal. The bare
// "create an archive" verb (7z a out.7z files) alone is everyday backup/packaging and
// floods FPs, so it no longer fires — only an explicit password flag (-p / -hp) does.
export const ARCHIVE_SUSPECT = /\b(7z|7za|winrar|rar)\b.*\s-h?p\S*/i;
