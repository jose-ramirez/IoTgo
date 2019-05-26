angular.module('iotgo')

.factory('Settings', [ '$location', function ($location) {
  var host = $location.host() + ':' + $location.port();
  var protocol = $location.protocol()
  var wsProtocol = protocol === 'https' ? 'wss' : 'ws'
  return {
    httpServer: `${protocol}://${host}`,
    websocketServer: `${wsProtocol}://${host}`
  };
} ]);
