from flask import current_app

from alerta.app import alarm_model
from alerta.models.alert import Alert

from alerta.webhooks  import WebhookBase

class FalcoWebhook(WebhookBase):
    """
    Falco webhook
    """

    def incoming(self, query_string, payload):

        if payload['importance_level'] == 'Critical':
            severity = 'critical'
        else:
            severity = 'warning'

        if payload['current_state'] == 'UP':
            severity = alarm_model.DEFAULT_NORMAL_SEVERITY

        return Alert(
            resource=payload['resource'],
            event=payload['current_state'],
            environment=current_app.config['DEFAULT_ENVIRONMENT'],
            severity=severity,
            service=['check_type'],
            group=payload['group'],
            value=payload['description'],
            text=f"{payload['importance_level']}: long_descriptio",
            tags=payload['tags'],
            origin=payload['origin'],
            correlate=['UP', 'DOWN'],
            #attributes={'checkId': 'check_id'},
            event_type=payload['event_type'],
            raw_data=payload
            )
