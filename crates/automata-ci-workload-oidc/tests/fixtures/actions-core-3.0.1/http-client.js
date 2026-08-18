export class HttpClient {
  constructor(userAgent, handlers) {
    this.userAgent = userAgent
    this.handlers = handlers
  }

  async getJson(url) {
    const request = {
      headers: {
        accept: 'application/json',
        'user-agent': this.userAgent
      }
    }
    for (const handler of this.handlers) {
      handler.prepareRequest(request)
    }
    const response = await fetch(url, {method: 'GET', headers: request.headers})
    const result = await response.json()
    if (!response.ok) {
      const error = new Error('HTTP request failed')
      error.statusCode = response.status
      throw error
    }
    return {statusCode: response.status, result}
  }
}
