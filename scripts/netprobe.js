// 临时：验证 netcfg 的接口探测逻辑（不修改任何系统配置）
const n = require('../src/engine/netcfg.js');
const { execFileSync } = require('child_process');

const alias = process.argv[2] || 'WLAN';
const idx = n.ifIndexByName(alias);
console.log(`${alias} 索引 =`, idx);
if (idx) {
  const out = execFileSync('powershell', [
    '-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command',
    `(Get-NetIPAddress -InterfaceIndex ${idx} -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -ExpandProperty IPAddress) -join ','`,
  ], { encoding: 'utf8' });
  console.log(`${alias} 地址 =`, out.trim());
}
console.log('默认网关 =', JSON.stringify(n.defaultGateway()));
console.log('是否管理员 =', n.isElevated());
