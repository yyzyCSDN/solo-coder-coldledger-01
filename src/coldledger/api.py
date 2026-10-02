from datetime import timedelta
from .inventory.fefo import reserve
from .quality.release import may_release
from .transport.connections import choose


class ColdLedgerService:
    def reserve_inventory(self, *args, **kwargs):
        return reserve(*args, **kwargs)

    def release_decision(self, *args, **kwargs):
        return may_release(*args, **kwargs)

    def next_connection(self, inbound, candidates, minutes):
        return choose(inbound, candidates, timedelta(minutes=minutes))

    def controlled_handoff_workflow(self, inventory=None, audit=None, authority=None):
        from .custody.controlled_handoff import ControlledHandoffWorkflow
        return ControlledHandoffWorkflow(inventory=inventory, audit=audit, authority=authority)

    def offline_credential_authority(self, secret=None, issuer="coldledger"):
        from .custody.offline_credentials import OfflineCredentialAuthority
        return OfflineCredentialAuthority(secret=secret, issuer=issuer)

    def health(self):
        return {'service': 'coldledger', 'status': 'ok', 'runtime_dependencies': 0}
