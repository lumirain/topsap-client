// 验证 koffi 的关键能力：调用原生函数、读写指针内存、输出参数
const koffi = require('koffi');

const k32 = koffi.load('kernel32.dll');

const GetTickCount = k32.func('uint32 GetTickCount()');
console.log('GetTickCount =', GetTickCount());

// 内存分配 + 写入 + 读出
const alloc = k32.func('void * LocalAlloc(uint32 uFlags, size_t uBytes)');
const ptr = alloc(0x40, 64);
console.log('LocalAlloc ->', koffi.address(ptr).toString(16));

const payload = Buffer.from([0x45, 0x00, 0x00, 0x3c, 0xab, 0xcd]);
try {
  koffi.encode(ptr, koffi.array('uint8_t', payload.length), payload);
  console.log('encode(array) OK');
} catch (e) {
  console.log('encode(array) 失败:', e.message);
  try {
    koffi.encode(ptr, 'uint8_t', Array.from(payload));
    console.log('encode(uint8_t) OK');
  } catch (e2) {
    console.log('encode(uint8_t) 失败:', e2.message);
  }
}

try {
  const out = koffi.decode(ptr, koffi.array('uint8_t', payload.length));
  console.log('decode(array) =', out && out.length, out && Array.from(out).map((n) => n.toString(16)));
} catch (e) {
  console.log('decode(array) 失败:', e.message);
  try {
    const out2 = koffi.decode(ptr, 'uint8_t', payload.length);
    console.log('decode(uint8_t,len) =', out2 && out2.length);
  } catch (e2) { console.log('decode(uint8_t,len) 失败:', e2.message); }
}

// 输出参数：模拟 _Out_ 指针
const QueryPerf = k32.func('bool QueryPerformanceCounter(_Out_ int64 *lpPerformanceCount)');
const holder = [0];
try {
  QueryPerf(holder);
  console.log('out param OK =', holder[0]);
} catch (e) { console.log('out param 失败:', e.message); }

// 缓冲区参数：把 Buffer 直接传成指针
const RtlZeroMemory = k32.func('void RtlZeroMemory(void *Destination, size_t Length)');
try {
  const buf = Buffer.alloc(8, 0xff);
  RtlZeroMemory(buf, buf.length);
  console.log('Buffer->pointer OK, 清零后 =', buf.toString('hex'));
} catch (e) { console.log('Buffer->pointer 失败:', e.message); }

console.log('可用 API:', Object.keys(koffi).filter((k) => typeof koffi[k] === 'function').join(', '));
