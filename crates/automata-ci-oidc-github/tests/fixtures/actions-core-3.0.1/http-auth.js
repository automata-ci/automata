export class BearerCredentialHandler {
  constructor(token) {
    this.token = token
  }

  prepareRequest(options) {
    options.headers.authorization = `Bearer ${this.token}`
  }
}
