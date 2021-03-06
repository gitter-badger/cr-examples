/**
 * Copyright (c) 2015, Bosch Software Innovations GmbH, Germany
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the Bosch Software Innovations GmbH, Germany nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
 * ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
'use strict';
(function () {
    var service = angular.module('crFeatureProperties', ['crCore', 'ngResource']);

    service.factory('Properties', function ($core, $resource) {
        var url = 'cr/1/things/:thingId/features/:featureId/properties';
        var actions = {
            get: {
                method: 'GET',
                params: {thingId: '@thingId', featureId: '@featureId'},
                interceptor: {
                    response: $core.interceptors.statusInterceptor
                }
            },
            put: {
                method: 'PUT',
                params: {thingId: '@thingId', featureId: '@featureId'},
                interceptor: {
                    response: $core.interceptors.statusInterceptor
                }
            },
            delete: {
                method: 'DELETE',
                params: {thingId: '@thingId', property: '@featureId'},
                interceptor: {
                    response: $core.interceptors.statusInterceptor
                }
            }
        };
        return $resource(url, null, actions);
    });

    service.factory('Property', function ($core, $resource) {
        var url = 'cr/1/things/:thingId/features/:featureId/properties/:jsonPointer';
        var actions = {
            get: {
                method: 'GET',
                params: {thingId: '@thingId', property: '@featureId', jsonPointer: '@jsonPointer'},
                interceptor: {
                    response: $core.interceptors.statusInterceptor
                }
            },
            put: {
                method: 'PUT',
                params: {thingId: '@thingId', property: '@featureId', jsonPointer: '@jsonPointer'},
                interceptor: {
                    response: $core.interceptors.statusInterceptor
                }
            },
            delete: {
                method: 'DELETE',
                params: {thingId: '@thingId', property: '@featureId', jsonPointer: '@jsonPointer'},
                interceptor: {
                    response: $core.interceptors.statusInterceptor
                }
            }
        };
        return $resource(url, null, actions);
    });
    
})();