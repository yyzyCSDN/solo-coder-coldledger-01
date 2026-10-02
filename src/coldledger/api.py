from datetime import timedelta
from .inventory.fefo import reserve
from .quality.release import may_release
from .transport.connections import choose
from .controlled.handoff_flow import HandoffFlow
from .storage.event_store import EventStore


class ColdLedgerService:
    def reserve_inventory(self,*args,**kwargs): return reserve(*args,**kwargs)
    def release_decision(self,*args,**kwargs): return may_release(*args,**kwargs)
    def next_connection(self,inbound,candidates,minutes): return choose(inbound,candidates,timedelta(minutes=minutes))

    @staticmethod
    def controlled_handoff_flow(event_store=None):
        """Replayable controlled-substance handoff flow (custody, offline
        credentials, inventory ledger and hash-chained audit as one log)."""
        return HandoffFlow(event_store or EventStore())

    def health(self): return {'service':'coldledger','status':'ok','runtime_dependencies':0}
