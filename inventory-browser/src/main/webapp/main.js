/*
 * Copyright (c) 2015 Bosch Software Innovations GmbH, Germany. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification, are permitted provided that the
 * following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following
 * disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the
 * following disclaimer in the documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the Bosch Software Innovations GmbH, Germany nor the names of its contributors may be used to
 * endorse or promote products derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

"use strict";

$(document).ready(function () {

    // --- Handler for refreshing details
    var refreshDetails = function () {
        var thingId = $("#details").attr("thingId");
        $.getJSON("cr/1/things/" + thingId).done(function (thing, textStatus) {

            $("#detailsThingId").text(thingId);

            var tablebody = $("#detailsTableBody");
            tablebody.empty();

            if ("attributes" in thing) {
                // --- for each attribute put row in details table
                var attrNames = Object.getOwnPropertyNames(thing.attributes);
                var first = true;
                attrNames.forEach(function (attribute) {
                    var value = thing.attributes[attribute];
                    var row = $("<tr>");
                    if (first) {
                        row.append($("<td rowspan=" + attrNames.length + ">").text("Attribute"));
                        first = false;
                    }
                    row.append($("<td>").text(attribute));
                    row.append($("<td>").text(typeof value == "object" ? JSON.stringify(value, null, 3) : value));
                    tablebody.append(row);
                });
            }
            if ("features" in thing) {
                // --- for each feature property put row in details table
                Object.getOwnPropertyNames(thing.features).forEach(function (featureId) {
                    var feature = thing.features[featureId];
                    if ("properties" in feature) {
                        var propNames = Object.getOwnPropertyNames(feature.properties);
                        var first = true;
                        propNames.forEach(function (prop) {
                            var value = feature.properties[prop];
                            var row = $("<tr>");
                            if (first) {
                                row.append($("<td rowspan=" + propNames.length + ">").text("Feature \"" + featureId + "\""));
                                first = false;
                            }
                            row.append($("<td>").text(prop));
                            row.append($("<td>").text(typeof value == "object" ? JSON.stringify(value, null, 3) : value));
                            tablebody.append(row);
                        });
                    }
                });
            }

            showThingDetails();
        }).fail(function () {
            hideThingDetails();
        });
    };

    // --- thing details and tenant assignment panels show/hide handlers
    function showThingDetails() {
        hideTenantAssignment();
        $("#table-wrapper").removeClass("col-md-12").addClass("col-md-6");
        $("#details").show();
    }
    function hideThingDetails() {
        $("#table-wrapper").removeClass("col-md-6").addClass("col-md-12");
        $("#details").hide();
    }
    function showTenantAssignment() {
        hideThingDetails();
        $("#table-wrapper").removeClass("col-md-12").addClass("col-md-6");
        $("#tenantAssignment").show();
    }
    function hideTenantAssignment() {
        $("#table-wrapper").removeClass("col-md-6").addClass("col-md-12");
        $("#tenantAssignment").hide();
    }

    // --- Handler for refreshing list and map of things
    var refreshTable = function () {

        $.getJSON("cr/1/search/things?fields=thingId,attributes/name,features/geolocation,features/orientation,features/xdk-sensors&option=limit(0,200)").done(function (data, textStatus) {

            // --- clear table content and clear map
            $("#tableBody").empty();
            if (markers != null) {
                map.removeLayer(markers);
            }

            // new marker layer on map
            markers = new L.FeatureGroup();
            map.addLayer(markers);

            // iterate of retrieved things
            var count = data.items.length;
            for (var i = 0; i < count; i++) {
                var t = data.items[i];
                var currentlySelected = (t.thingId == $("#details").attr("thingId"));

                // --- thing id column
                var row = $("<tr>");
                row.attr("thingId", t.thingId);
                row.append($("<td>").text(t.thingId));

                // --- checkbox column
                var checkbox = $("<input class='thingCheckbox' type='checkbox' />");
                checkbox.attr("value", t.thingId);
                checkbox.click(function(e) {
                    e.stopPropagation();
                });
                row.append($("<td>").append(checkbox));

                $("#tableBody").append(row);

                // --- when thing has a "geolocation" feature with "geoposition" properties
                if ("features" in t && "geolocation" in t.features && "geoposition" in t.features.geolocation.properties) {

                    // --- if latitude and longitude are available and are numbers then ..
                    var latitude = t.features.geolocation.properties.geoposition.latitude;
                    var longitude = t.features.geolocation.properties.geoposition.longitude;
                    if ((latitude -  parseFloat(latitude) + 1 >= 0) && (longitude -  parseFloat(longitude) + 1 >= 0)) {

                        // --- add marker for thing on map
                        var latlng = [t.features.geolocation.properties.geoposition.latitude,
                            t.features.geolocation.properties.geoposition.longitude];

                        // --- default marker (without "orientation")
                        var marker = L.marker(latlng);

                        // --- if xdk sensors and a value for light are available
                        if ("features" in t && "xdk-sensors" in t.features && "light" in t.features['xdk-sensors'].properties) {
                            var light = t.features['xdk-sensors'].properties.light;
                            var lightNormalized = (Math.log10(light) / 5);

                            var shadow = Math.floor(15 * lightNormalized);
                            var shadowNormalized = shadow > 0 ? shadow : 0;

                            //var style = "font-size: 30px; color: black; opacity: " + opacity + ";";
                            var style = "font-size: 30px; color: black; box-shadow: 0px 0px 25px " + shadowNormalized + "px rgba(255,255,0,1);";
                            var icon = L.divIcon({
                                className: "",
                                iconSize: null,
                                html: '<span class="icon-lightbulb" style="' + style + '" />'
                            });
                            marker = L.marker(latlng, {icon: icon, zIndexOffset: currentlySelected ? 1000 : 0});
                        }

                        // --- if direction is available and is a number then use rotated marker
                        if ("features" in t && "orientation" in t.features && "z" in t.features.orientation.properties) {
                            var direction = t.features.orientation.properties.z;
                            if (direction - parseFloat(direction) + 1 >= 0) {
                                var color =  currentlySelected ? "#D06245" : "#4597D0";
                                var style = "font-size: 30px; text-shadow: 3px 3px 3px black; color: " + color + "; transform-origin: 50% 0; transform: translate(-50%,0) rotate(" + direction + "deg);"
                                var icon = L.divIcon({
                                    className: "",
                                    iconSize: null,
                                    html: '<span class="glyphicon glyphicon-arrow-up" style="' + style + '" />'
                                });
                                marker = L.marker(latlng, {icon: icon, zIndexOffset: currentlySelected ? 1000 : 0});
                            }
                        }

                        marker._thingId = t.thingId;
                        marker.bindPopup(t.thingId);
                        marker.on("click", function (e) {
                            $("#details").attr("thingId", e.target._thingId);
                            refreshDetails();
                        });
                        marker.addTo(markers);
                    }
                }
            }

            if ($("#details").attr("thingId")) {
                refreshDetails();
            }

        });

        if ($("#autoRefresh").is(":checked")) {
            window.setTimeout(refreshTable, 1000);
        }
    };

    // --- create map
    var map = L.map("map");
    var osm = new L.TileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png", {
        minZoom: 5, maxZoom: 20,
        attribution: "Map data &copy; <a href=\"http://openstreetmap.org\">OpenStreetMap</a> contributors"
    });
    map.setView(new L.LatLng(47.682085, 9.386510), 13);
    map.addLayer(osm);
    var markers = null;

    $("#refreshTable").click(refreshTable);
    $("#autoRefresh").on("change", function () {
        if ($("#autoRefresh").is(":checked")) {
            window.setTimeout(refreshTable, 1000);
        }
    });

    $("#tableBody").on("click", "tr", function () {
        var row = $(this);
        var thingId = row.attr("thingId");

        // --- inactivate old row and activate clicked row
        $("#tableBody").find("tr.active").removeClass("active");
        row.addClass("active");

        // --- refresh thing details
        $("#details").attr("thingId", thingId);
        refreshDetails();
    });

    // --- tenant assignment panel related stuff
    $("#assignToTenant").click(function() {
        showTenantAssignment();
    });
    $("#doAssignThingsToTenant").click(function() {
        $(".thingCheckbox:checked").each(function(i,el) {
            console.log($(el).attr("value"));
        });
    });
    $("#cancelTenantAssignment").click(function() {
        hideTenantAssignment();
    });
    function initTenantsDropdown() {
        $.get( "im/1/rest/tenants", function(data) {
            $($.parseXML(data)).find("tenant").each(function(i,el) {
                var opt = $("<option/>").text($(el).find("name").text());
                $(opt).attr("value",$(el).find("id"));
                $("#tenantDropdown").append(opt);
            });
        });
    }

    refreshTable();
    initTenantsDropdown();

});