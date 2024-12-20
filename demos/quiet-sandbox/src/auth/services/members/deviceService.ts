/**
 * Handles device-related chain operations
 */

import getMAC from "getmac"
import { BaseChainService } from "../baseService.js"
import { Device, DeviceWithSecrets } from "@localfirst/auth"
import { SigChain } from "../../chain.js"

class DeviceService extends BaseChainService {
  public static init(sigChain: SigChain): DeviceService {
    return new DeviceService(sigChain)
  }

  /**
   * Generate a brand new QuietDevice for a given User ID
   * 
   * @param userId User ID that this device is associated with
   * @returns A newly generated QuietDevice instance
   */
  public static generateDeviceForUser(userId: string): DeviceWithSecrets {
    const params = {
      userId,
      deviceName: DeviceService.determineDeviceName()
    }

    return SigChain.lfa.createDevice(params)
  }

  /**
   * Get an identifier for the current device
   * 
   * @returns Formatted MAC address of the current device
   */
  public static determineDeviceName(): string {
    const mac = getMAC()
    return mac.replaceAll(':','')
  }

  public static redactDevice(device: DeviceWithSecrets): Device {
    return SigChain.lfa.redactDevice(device)
  }
}

export {
  DeviceService
}
