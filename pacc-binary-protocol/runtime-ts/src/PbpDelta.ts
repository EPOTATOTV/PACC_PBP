import { PbpCodec } from "./PbpCodec.js";
import { PbpDecoder } from "./PbpDecoder.js";
import { PbpEncoder } from "./PbpEncoder.js";
import type { PbpMessage } from "./PbpMessage.js";

/**
 * 差分编码的公共工具：字段比较与基线拷贝。
 *
 * <p>生成的 encodeDelta/applyDelta 只写「哪个字段变了」，比较与深拷贝的细节集中在这里。
 * 比较分两条路：标量/字符串/字节数组直接比较值；嵌套消息、列表、映射按「同一套编码调用
 * 写出来的字节」比较——它们的相等性与字段顺序、元素顺序天然一致。</p>
 */
export class PbpDelta {
  private constructor() {}

  /**
   * 两个字段是否不同：把同一套 writer 调用分别写进临时编码器，比字节。
   *
   * <p>生成代码里这样用：{@code PbpDelta.differs(x => x.writeStringList(events),
   * x => x.writeStringList(previous.events))}。</p>
   */
  static differs(current: (enc: PbpEncoder) => void, previous: (enc: PbpEncoder) => void): boolean {
    const a = new PbpEncoder(32);
    const b = new PbpEncoder(32);
    current(a);
    previous(b);
    return !PbpDelta.bytesEqual(a.toByteArray(), b.toByteArray());
  }

  /** 深拷贝消息（编解码往返）；null 原样返回，配合可空字段使用。 */
  static copy<T extends PbpMessage>(message: T | null, factory: () => T): T | null {
    if (message === null) {
      return null;
    }
    const clone = factory();
    clone.decode(new PbpDecoder(PbpCodec.payloadOf(message)));
    return clone;
  }

  /** 深拷贝消息列表；生成代码只在字段非空时调用，故入参非空。 */
  static copyList<T extends PbpMessage>(list: T[], factory: () => T): T[] {
    return list.map((element) => PbpDelta.copy(element, factory) as T);
  }

  /** 深拷贝消息映射的值；生成代码只在字段非空时调用，故入参非空。 */
  static copyMap<K, V extends PbpMessage>(map: Map<K, V>, factory: () => V): Map<K, V> {
    const clone = new Map<K, V>();
    for (const [key, value] of map) {
      clone.set(key, PbpDelta.copy(value, factory) as V);
    }
    return clone;
  }

  /** 字节数组相等比较。 */
  static bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
    if (a.length !== b.length) {
      return false;
    }
    for (let i = 0; i < a.length; i++) {
      if (a[i] !== b[i]) {
        return false;
      }
    }
    return true;
  }
}