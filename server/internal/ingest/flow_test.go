package ingest

import (
	"github.com/google/uuid"
	"openxdr/server/internal/flowinput"
	"strings"
	"testing"
	"time"
)

func TestFlowEnvelopeTrust(t *testing.T) {
	e, err := flowinput.Parse("ntopng", []byte(`{"IPV4_SRC_ADDR":"192.0.2.1","IPV4_DST_ADDR":"198.51.100.2","L4_SRC_PORT":1,"L4_DST_PORT":2,"PROTOCOL":17,"FIRST_SWITCHED":1794000000,"metadata":{"group_id":"fake"},"command_origin":{"id":"fake"}}`))
	if err != nil {
		t.Fatal(err)
	}
	origin := flowinput.Origin{GroupID: uuid.New(), Observer: "collector", Received: time.Now()}
	envelope := FlowEnvelope(origin, e)
	if err := envelope.Validate(); err != nil {
		t.Fatal(err)
	}
	if envelope.AssetID != nil || envelope.ProcessGUID != nil || envelope.ClassUID != 4001 {
		t.Fatalf("不应伪造归属: %+v", envelope)
	}
	if !strings.Contains(string(envelope.Raw), origin.GroupID.String()) {
		t.Fatal("应记录可信组")
	}
	again := FlowEnvelope(origin, e)
	if again.ID != envelope.ID {
		t.Fatal("重传必须幂等")
	}
	origin.GroupID = uuid.New()
	if FlowEnvelope(origin, e).ID == envelope.ID {
		t.Fatal("不同组不能合并")
	}
	envelope.Flow = nil
	if envelope.Validate() == nil {
		t.Fatal("缺失可信来源应拒绝")
	}
}
