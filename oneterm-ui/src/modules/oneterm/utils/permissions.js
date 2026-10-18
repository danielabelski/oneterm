import { PERMISSION_TYPE } from '@/modules/oneterm/views/systemSettings/accessControl/constants'

export function connectionPermissions(results) {
  return Object.fromEntries(Object.values(PERMISSION_TYPE).map(action => [action, results?.[action]?.allowed === true]))
}
