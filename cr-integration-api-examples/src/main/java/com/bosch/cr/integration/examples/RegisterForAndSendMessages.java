/* Copyright (c) 2011-2015 Bosch Software Innovations GmbH, Germany. All rights reserved. */
package com.bosch.cr.integration.examples;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.bosch.cr.integration.examples.model.ExampleUser;
import com.bosch.cr.integration.things.FeatureHandle;
import com.bosch.cr.integration.things.ThingHandle;
import com.bosch.cr.json.JsonFactory;
import com.bosch.cr.json.JsonValue;


/**
 * This examples shows the various possibilities that the {@code IntegrationClient} offers to register handlers for
 * {@link com.bosch.cr.model.messages.Message}s being sent to/from your {@code Thing}s, and shows how you can send
 * such {@code Message}s using the {@code IntegrationClient}.
 * <p>
 * NOTE: Make sure to invoke {@code IntegrationClient.subscriptions().consume()} once after all message handlers are
 * registered to start receiving events from Central Registry.
 */
public final class RegisterForAndSendMessages extends ExamplesBase
{
   private static final Logger LOGGER = LoggerFactory.getLogger(RegisterForAndSendMessages.class);

   private static final String ALL_THINGS_JSON_MESSAGE = "allThings_jsonMessage";
   private static final String ALL_THINGS_RAW_MESSAGE = "allThings_rawMessage";
   private static final String ALL_THINGS_STRING_MESSAGE = "allThings_stringMessage";
   private static final String MY_THING_JSON_MESSAGE = "myThing_jsonMessage";
   private static final String MY_THING_RAW_MESSAGE = "myThing_rawMessage";
   private static final String MY_THING_STRING_MESSAGE = "myThing_stringMessage";
   private static final String CUSTOM_SERIALIZER_EXAMPLE_USER_MESSAGE = "customSerializer_exampleUserMessage";

   /**
    * Shows various possibilities to register handlers for {@code Message}s of interest.
    */
   public void registerForMessages()
   {
      /* Register for *all* messages of *all* things and provide payload as JsonValue */
      thingIntegration.registerForMessage(ALL_THINGS_JSON_MESSAGE, "*", JsonValue.class, message -> {
         String subject = message.getSubject();
         JsonValue payload = message.getPayload().get();
         LOGGER.info("message for subject {} with payload {} received", subject, payload);
      });

      /* Register for messages with subject *subjectOfInterest* of *all* things and provide payload as raw ByteBuffer */
      thingIntegration.registerForMessage(ALL_THINGS_RAW_MESSAGE, "subjectOfInterest", message -> {
         String subject = message.getSubject();
         ByteBuffer payload = message.getRawPayload().get();
         LOGGER.info("message for subject {} with payload {} received", subject,
            StandardCharsets.UTF_8.decode(payload).toString());
      });

      /* Register for messages with subject *some.subject* of *all* things and provide payload as String */
      thingIntegration.registerForMessage(ALL_THINGS_STRING_MESSAGE, "some.subject", String.class, message -> {
         String subject = message.getSubject();
         String payload = message.getPayload().get();
         LOGGER.info("message for subject {} with payload {} received", subject, payload);
      });

      /* Register for *all* messages of a *specific* thing of and provide payload as JsonValue */
      myThing.registerForMessage(MY_THING_JSON_MESSAGE, "*", JsonValue.class, message -> {
         String subject = message.getSubject();
         JsonValue payload = message.getPayload().get();
         LOGGER.info("message for subject {} with payload {} received", subject, payload);
      });

      /* Register for *all* messages with subject *some_message_subject* of a *specific* thing and provide payload as raw ByteBuffer */
      myThing.registerForMessage(MY_THING_RAW_MESSAGE, "some_message_subject", message -> {
         String subject = message.getSubject();
         ByteBuffer payload = message.getPayload().get();
         LOGGER.info("message for subject {} with payload {} received", subject,
            StandardCharsets.UTF_8.decode(payload).toString());
      });

      /* Register for *all* messages of a *specific* thing and provide payload as String */
      myThing.registerForMessage(MY_THING_STRING_MESSAGE, "*", String.class, message -> {
         String subject = message.getSubject();
         String payload = message.getPayload().get();
         LOGGER.info("message for subject {} with payload {} received", subject, payload);
      });

      /*
       * Custom Message serializer usage:
       */

      /* Register for messages with subject *example.user.created* of *all* things and provide payload as custom type ExampleUser */
      thingIntegration
         .registerForMessage(CUSTOM_SERIALIZER_EXAMPLE_USER_MESSAGE, "example.user.created", ExampleUser.class,
            message -> {
               String subject = message.getSubject();
               ExampleUser user = message.getPayload().get();
               LOGGER.info("message for subject {} with payload {} received", subject, user);
            });
   }

   /**
    * Shows how to send a {@code Message} to/from a {@code Thing} using the {@code IntegrationClient}.
    */
   public void sendMessages()
   {
      /* Send a message *from* a thing with the given subject but without any payload */
      thingIntegration.message() //
         .from(":sendFromThisThing") //
         .subject("some.arbitrary.subject") //
         .send();

      /* Send a message *from* a feature with the given subject but without any payload */
      thingIntegration.message() //
         .from(":thingId") //
         .featureId("sendFromThisFeature") //
         .subject("justWantToLetYouKnow") //
         .send();

      /* Send a message *to* a thing with the given subject and text payload */
      thingIntegration.message() //
         .to("com.bosch.building:sprinklerSystem") //
         .subject("monitoring.building.fireAlert") //
         .payload("Roof is on fire") //
         .contentType("text/plain") //
         .send();

      /* Send a message *from* a feature with the given subject and json payload */
      thingIntegration.message() //
         .from("com.bosch.building.monitoring:fireDetectionDevice") //
         .featureId("smokeDetector") //
         .subject("fireAlert") //
         .payload(JsonFactory.readFrom("{\"action\" : \"call fire department\"}")) //
         .contentType("application/json") //
         .send();

      /* Send a message *to* a feature with the given subject and raw payload */
      thingIntegration.message() //
         .from("com.bosch.building.monitoring:fireDetectionDevice") //
         .featureId("smokeDetector") //
         .subject("fireAlert") //
         .payload(ByteBuffer.wrap("foo".getBytes(StandardCharsets.UTF_8))) //
         .contentType("application/octet-stream") //
         .send();

      final ThingHandle thingHandle = thingIntegration.forId(":thingId");
      /* Send a message *to* a thing (id already defined by the ThingHandle) with the given subject but without any payload */
      thingHandle.message() //
         .to() //
         .subject("somesubject") //
         .send();

      final FeatureHandle featureHandle = thingIntegration.forFeature(":thingId", "smokeDetector");
      /* Send a message *from* a feature with the given subject and text payload */
      featureHandle.message() //
         .from() //
         .subject("somesubject") //
         .payload("someContent") //
         .contentType("text/plain") //
         .send();

      /*
       * Custom Message serializer usage:
       */

      /* Send a message *from* a thing with the given subject and a custom payload type */
      thingIntegration.message() //
         .from(":userSender") //
         .subject("here.is.karl") //
         .payload(new ExampleUser("karl", "karl@bosch.com")).send();
   }
}
