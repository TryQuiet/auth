import { SigChain } from "../chain.js";

class BaseChainService {
  protected constructor(protected sigChain: SigChain) {}

  public static init(sigChain: SigChain, ...params: any[]): BaseChainService {
    throw new Error('init not implemented')
  }
}

export {
  BaseChainService
}