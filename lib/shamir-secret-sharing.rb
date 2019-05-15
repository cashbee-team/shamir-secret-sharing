require 'openssl'
require 'digest/sha1'

class ShamirSecretSharing
  VERSION = '0.1.0'

  def self.prime
    @prime ||= OpenSSL::BN.new('90298080309315418557060368684387169711767062077820047328483946136026783868610231658004529474715593165227045823796809053316421038435080529340276649188231489578413082915429082171276815832832032596987468328852992416302194653059769701301855112417280173119831084529497140275721119033981819754004876481947376857582541086674191309050669339147047177722482742095623467804455161314645495512219242738453400110821615485595951493732348640398317903244696668482247005070591932639428562532268906727083775005769341161737441206890423884947292116895278573352752642105943524899087988610386051326114173719939938357597470028921187928607042904261588275872786996786421015124382796026032641093550978376530319328301152270163150961443743005805156487456518852641096288933759632928527097707771705108593435811210969899009718025806082982491815839959394862199132189412760797205753603085181613915340914509742283721398758884882857717577570891251312844452052745163947127230739899990249592181831046734568185882323553723058313378711522655212295569618792861569553260909021907243424735691066494898818760523978370666490738958317270115402545013981689071761804217481237129399611746232468395365054918893973245564093211165225302041175079585458888691055939901734787886063765286977492815858172765414297704166310822063655804295492269403809136990123946872416301581476512804600437921871062337466733019509934199383005641657881387476608548204828441502666519703299105349809939561047193583345522023506184856674255042110783737263099438319847599648008766818797429771443705028772651586692324064007017187902934084171715785037116043811965267781489643030445117031408644673321057391176558036893857789298122893483373295134914414310225512185182855428723091437135258390607647079002628450028353308872465259623761042459298605601867079931599883341211337021548912929591032567679109586055855175707483614097894547800956575849455311488677165455115982505416964026617179448438285990610826073646616767534962613889972341177404511628350260670301108812261943592601817837534438293861144285248114026494593413438072008145151195558510253887426294107818889183153563906542962676822500733556368475553257951001559608026694402026083311647661603527141723939606662260781541702812518282966559303942883569550595968567624849771779902009005634939910112687785085261271077120292302150188079499520405255241734961072150325600567125813015450184377437377118236641143759546112499433705368329863240052878614034365965400707301060867667467921246288162184422787472727180885468250036866234631784065140572659371113921558324588343588649262665138554305162189719942919492935163152228273161856121456840243572074505539715086267815541055014575779183357826164049356330040472884738976674077057074492894659512026336932025359399208067756553441936121229276677493655969096449480584011430005309053544504304875804843205273883837061928391103734105527700616760751820474231999825032847945883064932406572688251330712502565439000257427471703412233595773324058194221908861303293341560475980198905863935850405064924144381710080649869192412763511460084172591012489581496077540366143109773048609220052015662328678967053922114059228108612468779055218472293622854582726541691332097684877156682496500546767264347154842487600035258894233822255723444907740808744398357482803391100715574412706233117206636112256824018335300077628867404705796199494183312134381338806813000075497747803240234241994282044442903373163715122536646305967943100639503123443493819526136342147706606394282112583884721431928417322993021536731405231184306729967529111955045252260102353296822531279058046816735479320770852433850566679904058973845613063366857995248536709558547947005487959070944758243881165013091044353829893545161327798124166213688912777335160265951849666987641506720154010364630736090984018386925406284136947816502665237274359499520079866122535658013617866311362943581086846194924950315777735026525882487543617430916255273833298323517701745687510934619838104831680724070326313574890013327805200827123185767256005905063632000378392141574495904804421309409555139440835558113898451033592526676935989162452243800981511319774846636555021940628714873179898475129018414822388672074777887836816908866710716135238849926550730803704711315750950458422935489673267976222635275704248820229824996510107205198663605380240651729687971710957296407610255077817146837349063148581060337597269343984345091912700819071375585519821604434603431994464701457318775403702846559037160195794889488908029233286151225725905398606350109962941753161584200144074269884326067022889478112825554120260952696169252329753222034898637234313852548016829410522468275347612080526487056946419000642199642660133237695390182834252238828073436204843551107043444186518737285718064454348783725196174064580015729871611222847895929389800649019254831014513113431655578925679204506338865404876491637286206819918930558503201366328626510435408373432348415238531403287283959561857892591427352842104554959608115380742631785942302014581426310009539709468373835178808015087703244680357716266673938316659211853843914796941131721320498518038272867994107029017543970812956754144964043650615822951424951757570100497007826364422530866395354057037623197190431202946206475807094227419540419168025621836505136395345095391267796526635539815975433875182503787461610057361924233524420270967631328159401123004381979801026089422686648542947429448884700847284807913378433322255357823885663399560901851919616533557061506731352057344807459911094519333689705182500885752770652880878560576235311015954069515891882699932824200620047914931186958185540784216011367774214867867886436031378064197674396368328035634225912051811470896936074219358317351694009621171355985142146081500737')
  end

  def self.pack(shares); shares; end
  def self.unpack(shares); shares; end
  def self.encode(string); string; end
  def self.decode(string); string; end

  def self.smallest_prime_of_bytelength(bytelength)
    n = OpenSSL::BN.new((2**(bytelength*8)+1).to_s)
    loop{ break if n.prime_fasttest?(20); n += 2 }
    n
  end

  def self.split(secret, available, needed, do_data_checksum=true)
    raise ArgumentError, "needed must be <= available" unless needed <= available
    raise ArgumentError, "needed must be >= 2"         unless needed >= 2
    raise ArgumentError, "available must be <= 250"    unless available <= 250

    if do_data_checksum
      checksum = Digest::SHA512.digest(secret)[0...2]
      num_bytes = secret.bytesize+2
      secret = OpenSSL::BN.new((checksum + secret).unpack("H*")[0], 16) rescue OpenSSL::BN.new("0")
      #num_bytes = secret.to_s(0).unpack("N")[0]
      raise ArgumentError, "bytelength of secret must be >= 1"   if num_bytes < 3
      raise ArgumentError, "bytelength of secret must be <= 4096" if num_bytes > 4097
    else
      num_bytes = secret.bytesize
      secret = OpenSSL::BN.new(secret.unpack("H*")[0], 16) rescue OpenSSL::BN.new("0") # without checksum
      raise ArgumentError, "bytelength of secret must be >= 1"   if num_bytes < 1
      raise ArgumentError, "bytelength of secret must be <= 4096" if num_bytes > 4096
    end

    coef = [ secret ] + Array.new(needed-1){ OpenSSL::BN.rand(num_bytes * 8) }

    shares = (1..available).map{|x|
      x = OpenSSL::BN.new(x.to_s)
      y = coef.each_with_index.inject(OpenSSL::BN.new("0")){|acc, (c, idx)|
        acc + c * x.mod_exp(idx, prime)
      } % prime
      [x, num_bytes, y]
    }
    pack(shares)
  end

  def self.combine(shares, do_raise=false, do_data_checksum=true)
    return false if shares.size < 2
    shares = unpack(shares)
    num_bytes = shares[0][1]

    secret = shares.inject(OpenSSL::BN.new("0")){|secret,(x,num_bytes,y)|
      l_x = l(x, shares, prime)
      summand = OpenSSL::BN.new(y.to_s).mod_mul(l_x, prime)
      secret = (secret + summand) % prime
    }
    if do_data_checksum
      checksum, secret = [ secret.to_s(16).rjust(num_bytes*2, '0') ].pack("H*").unpack("a2a*")
      checksum == Digest::SHA512.digest(secret)[0...2] ? secret : false
    else
      secret = [ secret.to_s(16).rjust(num_bytes*2, '0') ].pack("H*")
    end
  rescue ShareChecksumError, ShareDecodeError => ex
    raise if do_raise
    false
  end

  # Part of the Lagrange interpolation.
  # This is l_j(0), i.e.  # \prod_{x_j \neq x_i} \frac{-x_i}{x_j - x_i}
  # for more information compare Wikipedia: # http://en.wikipedia.org/wiki/Lagrange_form
  def self.l(current_x, shares, prime)
    shares.select{|x,num_bytes,y| x != current_x }.map{|x,num_bytes,y|
      minus_xi = OpenSSL::BN.new((-x).to_s)
      one_over_xj_minus_xi = OpenSSL::BN.new((current_x - x).to_s).mod_inverse(prime)
      minus_xi.mod_mul(one_over_xj_minus_xi, prime)
    }.inject{|p,f| p.mod_mul(f, prime) }
  end

  def self.encrypt(data, available, needed, key_bit_length=128)
    key = key_bit_length.is_a?(String) ? key_bit_length : [ OpenSSL::BN.rand(key_bit_length).to_s(16) ].pack("H*")
    c = OpenSSL::Cipher.new('aes-256-cbc').encrypt
    c.key, c.iv = Digest::SHA512.digest(key).unpack("a32a16")
    encrypted = c.update(data) << c.final
    [ split(key, available, needed), encode(encrypted) ]
  end

  def self.decrypt(shares, encrypted, do_raise=false)
    key = combine(shares, do_raise)
    return false unless key

    encrypted_decoded = decode(encrypted) rescue nil
    raise ShareDecodeError, "encrypted_data: #{encrypted}" unless encrypted_decoded

    return false unless encrypted and key
    c = OpenSSL::Cipher.new('aes-256-cbc').decrypt
    c.key, c.iv = Digest::SHA512.digest(key).unpack("a32a16")
    data = c.update(encrypted_decoded) << c.final
    data
  rescue OpenSSL::Cipher::CipherError, ShareDecodeError
    raise if do_raise
    false
  end

  def self.split_with_sanity_check(secret, available, needed, do_data_checksum=true)
    shares = split(secret, available, needed, do_data_checksum)
    success = true
    needed.upto(available).each{|n| shares.permutation(n).each{|shares| success = false if combine(shares) != secret } }
    (needed-1).downto(2).each{|n| shares.permutation(n).each{|shares| success = false if combine(shares) != false } }
    raise ShareSanityCheckError if success != true
    shares
  rescue ShareSanityCheckError
    retry
  end

  def self.encrypt_with_sanity_check(data, available, needed, key_bit_length=128)
    shares, encrypted = encrypt(data, available, needed, key_bit_length)
    success = true
    needed.upto(available).each{|n| shares.permutation(n).each{|shares| success = false if decrypt(shares, encrypted) != data } }
    (needed-1).downto(2).each{|n| shares.permutation(n).each{|shares| success = false if decrypt(shares, encrypted) != false } }
    raise ShareSanityCheckError if success != true
    [shares, encrypted]
  rescue ShareSanityCheckError
    retry
  end


  class Number < ShamirSecretSharing
    def self.split(secret, available, needed)
      num = OpenSSL::BN.new(secret.to_s)
      raise ArgumentError, "available must be <= 9"    unless available <= 9
      raise ArgumentError, "num too large. bytelength must be <= 9" unless num.num_bytes <= 9
      shares = ShamirSecretSharing.split([num.to_s(16)].pack("H*"), available, needed, do_data_checksum=nil)
      shares.map{|i| i.join.to_i }
    end

    def self.combine(shares)
      shares = shares.map{|i| i.to_s.match(/(\d)(\d)(\d+)/); [$1.to_i, $2.to_i, $3.to_i] }
      ShamirSecretSharing.combine(shares, do_raise=false, do_data_checksum=nil).unpack("H*")[0].to_i(16)
    end
  end

  class ShareChecksumError < ::StandardError; end
  class ShareDecodeError < ::StandardError; end
  class ShareSanityCheckError < ::StandardError; end

  class Packed < ShamirSecretSharing # packing format and checkum
    def self.pack(shares)
      shares.map{|x,num_bytes,y|
        buf = [ x, num_bytes, y.to_s(16) ].pack("CnH*")
        checksum = Digest::SHA512.digest(buf)[0...2]
        encode(checksum << buf)
      }
    end
    def self.unpack(shares)
      shares.map{|i|
        buf = decode(i) rescue nil
        raise ShareDecodeError, "share: #{i}" unless buf
        checksum, buf = buf.unpack("a2a*")
        raise ShareChecksumError, "share: #{i}" unless checksum == Digest::SHA512.digest(buf)[0...2]
        i = buf.unpack("CnH*"); [ i[0], i[1], i[2].to_i(16) ]
      }
    end
  end

  class Base58 < Packed
    def self.encode(string)
      string = string.unpack("H*")[0]
      leading_zero_bytes  = (string.match(/^([0]+)/) ? $1 : '').size / 2
      ("1"*leading_zero_bytes) + int_to_base58( string.to_i(16) )
    end
    def self.decode(string)
      leading_zero_bytes = (string.match(/^([1]+)/) ? $1 : '').size
      buf = base58_to_int(string).to_s(16); buf = (buf.bytesize.odd? ? '0'+buf : buf)
      [ ("00"*leading_zero_bytes) + buf ].pack("H*")
    end
    def self.int_to_base58(int_val, leading_zero_bytes=0)
      alpha, base58_val, base = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz", "", 58
      while int_val > 0
        int_val, remainder = int_val.divmod(base)
        base58_val = alpha[remainder] + base58_val
      end; base58_val
    end

    def self.base58_to_int(base58_val)
      alpha, base = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz", 58
      base58_val.reverse.each_char.with_index.inject(0) do |int_val, (char,index)|
        raise ArgumentError, 'Value not a valid Base58 String.' unless char_index = alpha.index(char)
        int_val + char_index*(base**index)
      end
    end
  end

  class Base64 < Packed
    def self.encode(string); [string].pack("m0"); end
    def self.decode(string); string.unpack("m0")[0]; end
  end

  class Hex < Packed
    def self.encode(string); string.unpack("H*")[0]; end
    def self.decode(string); [string].pack("H*"); end
  end
end




if $0 == __FILE__
  require "minitest/autorun"

  class MiniTest::Unit::TestCase
    def assert_raises_and_message(klass, msg, &blk)
      err = assert_raises(klass, &blk); assert_equal msg, err.message
    end
  end


  class TestShamirSecretSharing < MiniTest::Unit::TestCase

    def helper(&b)
      [ [6,3], [10, 2], [3,2], [100, 30] ].each{|available,needed| b.call(available, needed) }
    end


    def test_shamir_base58
      secret = "hello"
      helper{|available,needed|
        shares = ShamirSecretSharing::Base58.split(secret, available, needed)
        assert_equal secret, ShamirSecretSharing::Base58.combine(shares.shuffle[0...needed])
      }

      shares = ShamirSecretSharing::Base58.split_with_sanity_check(secret, available=3, needed=2)
      assert_equal secret, ShamirSecretSharing::Base58.combine(shares.shuffle[0...needed])
    end

    def test_shamir_base64
      secret = "hello"
      helper{|available,needed|
        shares = ShamirSecretSharing::Base64.split(secret, available, needed)
        assert_equal secret, ShamirSecretSharing::Base64.combine(shares.shuffle[0...needed])
      }
    end

    def test_shamir_hex
      secret = "hello"
      helper{|available,needed|
        shares = ShamirSecretSharing::Hex.split(secret, available, needed)
        assert_equal secret, ShamirSecretSharing::Hex.combine(shares.shuffle[0...needed])
      }
    end

    def test_shamir_number
      secret = 123
      shares = ShamirSecretSharing::Number.split(secret, 6, 3)
      assert_equal secret, ShamirSecretSharing::Number.combine(shares.shuffle[0...3])
    end

    def test_shamir_base58_encrypt
      text = "A"*32
      helper{|available,needed|
        shares, encrypted = ShamirSecretSharing::Base58.encrypt(text, available, needed, 96)
        assert_equal text, ShamirSecretSharing::Base58.decrypt(shares.shuffle[0...needed], encrypted)
      }

      shares, encrypted = ShamirSecretSharing::Base58.encrypt_with_sanity_check(text, available=3, needed=2)
      assert_equal text, ShamirSecretSharing::Base58.decrypt(shares.shuffle[0...needed], encrypted)
    end

    def test_shamir_base58_encrypt_sanity_checks
      klass = ShamirSecretSharing::Base58
      checks, success = 5, true
      [
        [2,3], [2,4], [3,5]
      ].each{|needed,available|
        checks.times{
          data = "A"*32
          shares, encrypted = klass.encrypt(data, available, needed, 96)
          needed.upto(available).each{|n|
            shares.permutation(n).each{|shares| success = false if klass.decrypt(shares, encrypted, true) != data }
          }
          (needed-1).downto(2).each{|n|
            shares.permutation(n).each{|shares| success = false if klass.decrypt(shares, encrypted, true) != false }
          }
          break unless success
        }
      }
      assert_equal true, success
    end

    def test_shamir_base64_encrypt
      text = "A"*32
      helper{|available,needed|
        shares, encrypted = ShamirSecretSharing::Base64.encrypt(text, available, needed, 96)
        assert_equal text, ShamirSecretSharing::Base64.decrypt(shares.shuffle[0...needed], encrypted)
      }
    end

    def test_shamir_hex_encrypt
      text = "A"*32
      helper{|available,needed|
        shares, encrypted = ShamirSecretSharing::Hex.encrypt(text, available, needed, 96)
        assert_equal text, ShamirSecretSharing::Hex.decrypt(shares.shuffle[0...needed], encrypted)
      }
    end

    def test_shamir_with_broken_share_checksum
      secret = "hello"
      share_with_broken_checksum = ShamirSecretSharing::Base58.encode("foobar")
      share_with_broken_encoding = "1Il"
      shares = ShamirSecretSharing::Base58.split(secret, 3, 2)
      assert_equal false, ShamirSecretSharing::Base58.combine( [shares.shuffle.first, share_with_broken_checksum])
      assert_equal false, ShamirSecretSharing::Base58.combine( [shares.shuffle.first, share_with_broken_encoding])

      do_raise = true
      err = assert_raises(ShamirSecretSharing::ShareChecksumError){ ShamirSecretSharing::Base58.combine( [shares.shuffle.first, share_with_broken_checksum], do_raise) }
      assert_match /share: /, err.message
      assert_raises(ShamirSecretSharing::ShareDecodeError){ ShamirSecretSharing::Base58.combine( [shares.shuffle.first, share_with_broken_encoding], do_raise) }
      assert_match /share: /, err.message
    end

    def test_shamir_encrypt_with_broken_encypted_data
      text = "A"*32
      broken_encrypted_data = ShamirSecretSharing::Base58.encode("foobar")
      broken_encrypted_data_encoding = "1Il"
      share_with_broken_encoding = "1Il"
      shares, encrypted = ShamirSecretSharing::Base58.encrypt(text, 3, 2, 96)
      assert_equal false, ShamirSecretSharing::Base58.decrypt(shares.shuffle[0...2], broken_encrypted_data)
      assert_equal false, ShamirSecretSharing::Base58.decrypt(shares.shuffle[0...2], broken_encrypted_data_encoding)

      do_raise = true
      assert_raises(OpenSSL::Cipher::CipherError) { ShamirSecretSharing::Base58.decrypt(shares.shuffle[0...2], broken_encrypted_data, do_raise) }
      err = assert_raises(ShamirSecretSharing::ShareDecodeError){ ShamirSecretSharing::Base58.decrypt( [shares.shuffle.first, share_with_broken_encoding], encrypted, do_raise) }
      assert_match /share: /, err.message
      err = assert_raises(ShamirSecretSharing::ShareDecodeError){ ShamirSecretSharing::Base58.decrypt(shares.shuffle[0...2], broken_encrypted_data_encoding, do_raise) }
      assert_match /encrypted_data: /, err.message
    end

    def test_shamir_split_argument_errors
      assert_raises_and_message(ArgumentError, "needed must be <= available")            { ShamirSecretSharing::Base58.split("foobar", 2, 3)   }
      assert_raises_and_message(ArgumentError, "needed must be >= 2")                    { ShamirSecretSharing::Base58.split("foobar", 3, 1)   }
      assert_raises_and_message(ArgumentError, "available must be <= 250")               { ShamirSecretSharing::Base58.split("foobar", 251, 2) }
      assert_raises_and_message(ArgumentError, "bytelength of secret must be >= 1")      { ShamirSecretSharing::Base58.split("", 3, 2)         }
      assert_raises_and_message(ArgumentError, "bytelength of secret must be <= 4096")   { ShamirSecretSharing::Base58.split("A"*4097, 3, 2)          }
    end

  end

=begin
  require 'pp'

  pp shares = ShamirSecretSharing::Base58.split("hello", 6, 3)
  pp ShamirSecretSharing::Base58.combine(shares[0...3])

  pp shares = ShamirSecretSharing::Base64.split("hello", 6, 3)
  pp ShamirSecretSharing::Base64.combine(shares[0...3])

  pp shares = ShamirSecretSharing::Hex.split("hello", 6, 3)
  pp ShamirSecretSharing::Hex.combine(shares[0...3])

  pp shares = ShamirSecretSharing::Number.split(123, 6, 3)
  pp ShamirSecretSharing::Number.combine(shares[0...3])


  shares, encrypted = ShamirSecretSharing::Base58.encrypt("A"*32, 6, 3, 96)
  pp [shares, encrypted]
  p ShamirSecretSharing::Base58.decrypt(shares.shuffle[0...3], encrypted)

  shares, encrypted = ShamirSecretSharing::Base64.encrypt("A"*32, 6, 3, 96)
  pp [shares, encrypted]
  p ShamirSecretSharing::Base64.decrypt(shares.shuffle[0...3], encrypted)

  shares, encrypted = ShamirSecretSharing::Hex.encrypt("A"*32, 6, 3, 96)
  pp [shares, encrypted]
  p ShamirSecretSharing::Hex.decrypt(shares.shuffle[0...3], encrypted)
=end

end
