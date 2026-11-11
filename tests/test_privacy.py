from shielded_mempool.privacy import simulate, experiment

def test_linkage_measures_and_assumptions():
    data=experiment(samples=100,seed=123)
    assert len(data)==5
    assert data[-1]['linked_fraction'] is None
    assert data[0]['linked_fraction'] is not None
    assert data[1]['mean_padding_bytes'] > 0
    assert data[2]['mean_added_delay_ms'] > data[0]['mean_added_delay_ms']
    assert simulate('direct',samples=50,seed=9)==simulate('direct',samples=50,seed=9)
