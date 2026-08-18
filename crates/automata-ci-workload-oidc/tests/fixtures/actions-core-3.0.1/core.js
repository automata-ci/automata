export const registeredSecrets = []

export function debug(_message) {}

export function setSecret(value) {
  registeredSecrets.push(value)
}
