class A
  def m(*a); end
end
class B < A
  def m(a1, a2)
    p2 = proc { super }
    p2.call
  end
end
def go(b, n)
  return b.m(1, 2) if n == 0
  go(b, n - 1)
end
begin
  go(B.new, ARGV[0].to_i)
  puts "END OK"
rescue => e
  puts "RESCUE: #{e.class}"
end
