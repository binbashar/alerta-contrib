from flask import current_app

from alerta.app import alarm_model
from alerta.models.alert import Alert

from alerta.webhooks  import WebhookBase

class FalcoWebhook(WebhookBase):
    """
    Falco webhook
    """

    def incoming(self, path, query_string, payload):

        if payload['importance_level'] == 'HIGH':
            severity = 'critical'
        else:
            severity = 'warning'

        if payload['current_state'] == 'UP':
            severity = alarm_model.DEFAULT_NORMAL_SEVERITY

        return Alert(
            resource="tuvieja",
            event=payload['current_state'],
            correlate=['UP', 'DOWN'],
            environment=current_app.config['DEFAULT_ENVIRONMENT'],
            severity=severity,
            service=['check_type'],
            group='Network',
            value='description',
            text=f"{payload['importance_level']}: long_descriptio",
            tags='tags',
            attributes={'checkId': 'check_id'},
            origin='Falco',
            event_type='availabilityAlert',
            raw_data=payload
            )
        #return Alert(
        #)
