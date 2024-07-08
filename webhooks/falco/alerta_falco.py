from flask import current_app

from alerta.app import alarm_model
from alerta.models.alert import Alert

from alerta.webhooks  import WebhookBase

class FalcoWebhook(WebhookBase):
    """
    Falco webhook
    """

    def incoming(self, query_string, payload):

        if payload['importance_level'] == 'HIGH':
            severity = 'critical'
        else:
            severity = 'warning'

        if payload['current_state'] == 'UP':
            severity = alarm_model.DEFAULT_NORMAL_SEVERITY

        return Alert(
            origin='Falco',
            event_type='availabilityAlert',
            raw_data=payload
            )
        #return Alert(
        #    resource=payload['check_name'],
        #    event=payload['current_state'],
        #    correlate=['UP', 'DOWN'],
        #    environment=current_app.config['DEFAULT_ENVIRONMENT'],
        #    severity=severity,
        #    service=[payload['check_type']],
        #    group='Network',
        #    value=payload['description'],
        #    text=f"{payload['importance_level']}: {payload['long_description']}",
        #    tags=payload['tags'],
        #    attributes={'checkId': payload['check_id']},
        #    origin='Falco',
        #    event_type='availabilityAlert',
        #    raw_data=payload
        #)
